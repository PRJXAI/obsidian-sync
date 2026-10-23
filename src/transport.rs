//! Bounded connection transport; the LiveSync protocol router is supplied by startup.
use crate::Result;
use axum::Router;
use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore},
    time::Sleep,
};

pub async fn serve(
    address: SocketAddr,
    app: Router,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<()> {
    let listener = LimitedListener {
        inner: TcpListener::bind(address).await?,
        slots: Arc::new(Semaphore::new(64)),
    };
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await?;
    Ok(())
}
struct LimitedListener {
    inner: TcpListener,
    slots: Arc<Semaphore>,
}
impl axum::serve::Listener for LimitedListener {
    type Io = BoundedConnection;
    type Addr = SocketAddr;
    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match self.inner.accept().await {
                Ok((inner, address)) => {
                    if let Ok(permit) = self.slots.clone().try_acquire_owned() {
                        return (
                            BoundedConnection {
                                inner,
                                _permit: permit,
                                deadline: Box::pin(tokio::time::sleep(Duration::from_secs(90))),
                            },
                            address,
                        );
                    }
                    // Drop excess connections rather than allocating tasks or waiters.
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
    }
    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}
struct BoundedConnection {
    inner: TcpStream,
    _permit: OwnedSemaphorePermit,
    deadline: Pin<Box<Sleep>>,
}
impl BoundedConnection {
    fn expired(&mut self, cx: &mut Context<'_>) -> bool {
        self.deadline.as_mut().poll(cx).is_ready()
    }
}
impl AsyncRead for BoundedConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.expired(cx) {
            return Poll::Ready(Err(io::ErrorKind::TimedOut.into()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
impl AsyncWrite for BoundedConnection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.expired(cx) {
            return Poll::Ready(Err(io::ErrorKind::TimedOut.into()));
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
