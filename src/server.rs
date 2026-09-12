//! Connection ownership keeps response writes, admission and shutdown bounded.
use crate::http::{ConnectionContext, HttpState, router};
use axum::Extension;
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    service::TowerToHyperService,
};
use std::{
    future::Future,
    io,
    sync::{Arc, Mutex},
};
use tokio::{
    net::TcpListener,
    sync::{Semaphore, watch},
    time::{Instant, timeout_at},
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

pub async fn serve(
    listener: TcpListener,
    state: HttpState,
    shutdown: impl Future<Output = ()> + Send,
) -> io::Result<()> {
    let connections = TaskTracker::new();
    let stop_connections = CancellationToken::new();
    let capacity = Arc::new(Semaphore::new(
        state
            .service
            .config
            .max_concurrent_requests
            .saturating_mul(2)
            .saturating_add(2)
            .min(Semaphore::MAX_PERMITS),
    ));
    let app = router(state.clone());
    let maintenance = {
        let service = state.service.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            interval.tick().await;
            loop {
                tokio::select! {
                    _ = service.stopping.cancelled() => break,
                    _ = interval.tick() => {
                        if service.storage.cleanup(Instant::now() + service.config.storage_timeout).await.is_err() {
                            tracing::warn!(code = "storage_unavailable", "cache_cleanup_failed");
                        }
                    }
                }
            }
        })
    };
    tokio::pin!(shutdown);
    let accept_result = loop {
        tokio::select! {
            _ = &mut shutdown => break Ok(()),
            _ = state.service.stopping.cancelled() => break Ok(()),
            accepted = listener.accept() => {
                let (socket, _) = match accepted { Ok(connection) => connection, Err(error) => break Err(error) };
                let Ok(socket_permit) = capacity.clone().try_acquire_owned() else {
                    // Do not create another task for overloaded connections or await a slow reader.
                    let id = uuid::Uuid::new_v4();
                    let body = format!("{{\"request_id\":\"{id}\",\"error\":{{\"code\":\"service_overloaded\",\"message\":\"Service capacity is exhausted.\",\"retryable\":true,\"retry_after_seconds\":1}}}}");
                    let reply = format!("HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nX-Request-ID: {id}\r\nRetry-After: 1\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}", body.len());
                    if socket.try_write(reply.as_bytes()).is_err() { tracing::debug!("overloaded_connection_closed"); }
                    continue;
                };
                let (deadline, mut deadline_rx) = watch::channel(None);
                let context = ConnectionContext { deadline, permit: Arc::new(Mutex::new(None)) };
                let application = app.clone().layer(Extension(context.clone()));
                let stop = stop_connections.clone();
                let request_timeout = state.service.config.request_timeout;
                let response_timeout = state.service.config.response_write_timeout;
                connections.spawn(async move {
                    let _socket_permit = socket_permit;
                    let mut builder = hyper::server::conn::http1::Builder::new();
                    // One request per connection gives each response an unambiguous flush owner.
                    builder.keep_alive(false).timer(TokioTimer::new()).header_read_timeout(request_timeout).max_buf_size(32 * 1024);
                    let connection = builder.serve_connection(TokioIo::new(socket), TowerToHyperService::new(application));
                    tokio::pin!(connection);
                    let timer = tokio::time::sleep(request_timeout + response_timeout);
                    tokio::pin!(timer);
                    loop {
                        tokio::select! {
                            result = &mut connection => { if result.is_err() { tracing::debug!("connection_closed"); } break; }
                            _ = stop.cancelled() => break,
                            _ = &mut timer => { tracing::warn!("connection_deadline_exceeded"); break; }
                            changed = deadline_rx.changed() => {
                                if changed.is_err() { break; }
                                if let Some(deadline) = *deadline_rx.borrow_and_update() { timer.as_mut().reset(deadline); }
                            }
                        }
                    }
                    // The context keeps its admission permit until flush, disconnect, or timeout.
                    context.permit.lock().unwrap_or_else(|e| e.into_inner()).take();
                });
            }
        }
    };
    state.service.begin_shutdown();
    connections.close();
    let deadline = Instant::now() + state.service.config.shutdown_grace;
    tracing::info!(active_connections = connections.len(), "shutdown_drain");
    let drain = async {
        tokio::join!(state.service.drain(deadline), connections.wait());
    };
    if timeout_at(deadline, drain).await.is_err() {
        tracing::warn!(cancelled_connections = connections.len(), "shutdown_cancel");
        state.service.cancel();
        stop_connections.cancel();
    }
    connections.wait().await;
    state.service.drain(deadline).await;
    if maintenance.await.is_err() {
        tracing::warn!("maintenance_task_failed");
    }
    state.service.storage.close().await;
    tracing::info!("shutdown_complete");
    accept_result
}
