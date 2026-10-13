use std::{
    collections::HashMap,
    io::{self, ErrorKind},
    num::NonZeroU32,
    pin::Pin,
    sync::{Arc, Mutex as SyncMutex},
    task::{Context, Poll},
};

use async_broadcast::{Receiver, Sender, broadcast};
use futures_core::Future;
use futures_lite::Stream;
use ordered_stream::OrderedFuture;

use crate::{Error, Message, Result, message::Sequence};

#[derive(Clone, Debug)]
pub struct PendingMethodCalls {
    inner: Arc<SyncMutex<PendingMethodCallsState>>,
    keyring_wire: bool,
}

impl PendingMethodCalls {
    pub fn register_call(
        &self,
        serial: NonZeroU32,
    ) -> impl Future<Output = Result<Message>>
    + OrderedFuture<Output = Result<Message>, Ordering = Sequence> {
        use std::collections::hash_map::Entry;

        let (reply_sender, reply_receiver) = broadcast(1);
        let mut registered = false;
        let closed_error = {
            let mut state = self.inner.lock().unwrap();
            if let Some(error) = &state.closed_error {
                Some(error.clone())
            } else if self.keyring_wire && (reply_sender.capacity() != 1
                || reply_receiver.capacity() != 1 || !state.calls.is_empty()
                || (state.calls.capacity() != 0 && state.calls.capacity() != 3)) {
                Some(Error::ExcessData)
            } else {
                // The source-bound four-bucket table is also checked at actual
                // creation/reuse. There can be only one pending bounded call.
                if self.keyring_wire && (state.calls.try_reserve(1).is_err() || state.calls.capacity() != 3) {
                    Some(Error::ExcessData)
                } else {
                match state.calls.entry(serial) {
                    Entry::Vacant(entry) => {
                        entry.insert(reply_sender.clone());
                        registered = true;
                    }
                    Entry::Occupied(_) => {
                        unreachable!(
                            "Serial number `{serial}` reused while a method call is still pending"
                        );
                    }
                }

                None
                }
            }
        };

        if let Some(error) = closed_error {
            send_reply(reply_sender, Sequence::LAST, Err(error));
        }

        PendingMethodCall {
            serial, registered,
            reply_receiver,
            pending_method_calls: self.clone(),
        }
    }

    pub fn complete_call(&self, serial: NonZeroU32, ordering: Sequence, reply: Result<Message>) {
        let reply_sender = self.inner.lock().unwrap().calls.remove(&serial);
        let Some(reply_sender) = reply_sender else {
            return;
        };

        send_reply(reply_sender, ordering, reply);
    }

    /// Consume the matching original registration BEFORE materializing an error
    /// detail. An unsolicited Error remains only a bounded raw Message on the
    /// ordered stream; it cannot allocate a second retained MethodError String.
    pub(super) fn complete_message(&self, message: &Message) {
        if !matches!(message.message_type(), crate::message::Type::MethodReturn | crate::message::Type::Error) {
            return;
        }
        let Some(serial) = message.header().reply_serial() else { return; };
        let sender = self.inner.lock().unwrap().calls.remove(&serial);
        let Some(sender) = sender else { return; };
        let result = match message.message_type() {
            crate::message::Type::MethodReturn => Ok(message.clone()),
            crate::message::Type::Error => Err(message.clone().into()),
            _ => return,
        };
        send_reply(sender, message.recv_position(), result);
    }

    pub fn fail_all(&self, error: Error) {
        let reply_senders: Vec<_> = {
            let mut state = self.inner.lock().unwrap();
            state.closed_error.get_or_insert_with(|| error.clone());
            state
                .calls
                .drain()
                .map(|(_, reply_sender)| reply_sender)
                .collect()
        };

        for reply_sender in reply_senders {
            send_reply(reply_sender, Sequence::LAST, Err(error.clone()));
        }
    }

    fn remove_call(&self, serial: NonZeroU32) {
        self.inner.lock().unwrap().calls.remove(&serial);
    }
}

#[cfg(all(unix, feature = "tokio"))]
pub(super) const fn keyring_control_layouts() -> [crate::keyring_wire::control::TypeLayout; 4] {
    use crate::keyring_wire::control::TypeLayout;
    [TypeLayout::of::<SyncMutex<PendingMethodCallsState>>(),
        TypeLayout::of::<(PendingMethodReply, usize)>(),
        TypeLayout::of::<(NonZeroU32, PendingMethodReplySender)>(),
        TypeLayout::of::<PendingMethodReplySender>()]
}

impl PendingMethodCalls {
    pub(super) fn with_keyring_wire(keyring_wire: bool) -> Self {
        Self { inner: Arc::new(SyncMutex::new(PendingMethodCallsState::default())), keyring_wire }
    }
}

impl Default for PendingMethodCalls {
    fn default() -> Self {
        Self::with_keyring_wire(false)
    }
}

/// A method call whose completion can be awaited or joined with other streams.
///
/// This is useful for cache population method calls, where joining the call with an update signal
/// stream can be used to ensure that cache updates are not overwritten by a cache population whose
/// task is scheduled later.
#[derive(Debug)]
struct PendingMethodCall {
    serial: NonZeroU32,
    registered: bool,
    reply_receiver: Receiver<PendingMethodReply>,
    pending_method_calls: PendingMethodCalls,
}

impl Drop for PendingMethodCall {
    fn drop(&mut self) {
        if self.registered { self.pending_method_calls.remove_call(self.serial); }
    }
}

impl Future for PendingMethodCall {
    type Output = Result<Message>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.poll_before(cx, None).map(|ret| {
            ret.map(|(_, r)| r).unwrap_or_else(|| {
                Err(Error::InputOutput(
                    io::Error::new(ErrorKind::BrokenPipe, "socket closed").into(),
                ))
            })
        })
    }
}

impl OrderedFuture for PendingMethodCall {
    type Output = Result<Message>;
    type Ordering = Sequence;

    fn poll_before(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        before: Option<&Self::Ordering>,
    ) -> Poll<Option<(Self::Ordering, Self::Output)>> {
        let this = self.get_mut();

        match Pin::new(&mut this.reply_receiver).poll_next(cx) {
            Poll::Ready(Some(reply)) => Poll::Ready(Some(reply)),
            Poll::Ready(None) => Poll::Ready(None),
            // `before` is only provided after another stream has produced that sequence. Since the
            // socket reader dispatches replies synchronously as it reads messages, any earlier
            // matching reply would already be queued above. For `OrderedFuture`, `Ready(None)` is
            // the `NoneBefore` equivalent; return it only after polling the receiver so the current
            // task is still woken when the reply arrives.
            Poll::Pending if before.is_some() => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[derive(Debug, Default)]
struct PendingMethodCallsState {
    calls: HashMap<NonZeroU32, PendingMethodReplySender>,
    closed_error: Option<Error>,
}

type PendingMethodReply = (Sequence, Result<Message>);
type PendingMethodReplySender = Sender<PendingMethodReply>;

fn send_reply(reply_sender: PendingMethodReplySender, ordering: Sequence, reply: Result<Message>) {
    let _ = reply_sender.try_broadcast((ordering, reply));
}

#[cfg(all(unix, feature = "tokio", any(test, feature = "mrk-owned-test-support")))]
#[cfg_attr(test, test)]
pub(super) fn keyring_error_completion_consumes_only_the_matching_registration() {
    let calls = PendingMethodCalls::with_keyring_wire(true);
    let request = Message::method_call("/", "Lookup").unwrap().build(&()).unwrap();
    let serial = request.primary_header().serial_num();
    let error = Message::error(&request.header(), "org.example.Refused").unwrap()
        .keyring_wire(true).build(&"synthetic refusal").unwrap();
    let mut cx = Context::from_waker(std::task::Waker::noop());
    {
        let mut pending = std::pin::pin!(calls.register_call(serial));
        assert_eq!(calls.inner.lock().unwrap().calls.capacity(), 3);
        assert!(pending.as_mut().poll(&mut cx).is_pending());
        {
            let mut refused = std::pin::pin!(calls.register_call(serial));
            assert!(matches!(refused.as_mut().poll(&mut cx), Poll::Ready(Err(Error::ExcessData))));
        }
        // Refusing a second bounded registration must not remove the first
        // original when the refused future is dropped, even for the same ID.
        assert_eq!(calls.inner.lock().unwrap().calls.len(), 1);
        calls.complete_message(&error);
        assert!(calls.inner.lock().unwrap().calls.is_empty());
        // The duplicate has no matching sender, so it stays raw and cannot create
        // another retained error-detail allocation or a second queued completion.
        calls.complete_message(&error);
        let Poll::Ready(Err(Error::MethodError(_, Some(detail), original))) = pending.as_mut().poll(&mut cx)
            else { panic!("expected one original error completion"); };
        assert_eq!(detail, "synthetic refusal");
        assert_eq!(original.data().as_ptr(), error.data().as_ptr());
    } // Dispose the actual first receiver, not only a Pin<&mut _> handle.

    let next = Message::method_call("/", "Lookup").unwrap().build(&()).unwrap();
    let mut pending = std::pin::pin!(calls.register_call(next.primary_header().serial_num()));
    assert_eq!(calls.inner.lock().unwrap().calls.capacity(), 3);
    calls.complete_message(&error); // Old/unsolicited Error cannot consume next.
    assert!(pending.as_mut().poll(&mut cx).is_pending());
    assert_eq!(calls.inner.lock().unwrap().calls.len(), 1);
    let reply = Message::method_return(&next.header()).unwrap().keyring_wire(true).build(&()).unwrap();
    calls.complete_message(&reply);
    let Poll::Ready(Ok(original)) = pending.as_mut().poll(&mut cx) else { panic!("expected original reply"); };
    assert_eq!(original.data().as_ptr(), reply.data().as_ptr());
    assert!(calls.inner.lock().unwrap().calls.is_empty());
}
