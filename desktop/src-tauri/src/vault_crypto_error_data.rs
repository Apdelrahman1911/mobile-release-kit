#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error { Format, Authentication, Random, Bounds, Allocation }
