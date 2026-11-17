use core::error::Error;

use tc_agreement::AgreementInit;

use crate::agreement::Agreement;
use crate::{AlgoError, ErrorKind, Params};

// What a row's init leaves: an agreement initialized over one type of key, which takes the other
// side's key as one type of params
pub(super) trait Inner {
    fn agreement_size(&self) -> usize;

    fn calculate(&self, public_key: &dyn Params, output: &mut [u8]) -> Result<(), AlgoError>;
}

struct Typed<A>(A);

impl<A> Inner for Typed<A>
where
    A: tc_agreement::Agreement,
    A::PublicKey: Sized + 'static,
    A::Error: Error + Send + Sync + 'static,
{
    fn agreement_size(&self) -> usize {
        self.0.agreement_size()
    }

    // The other side's key of another type, or on another curve, is InvalidParams, and so is any
    // failure of the agreement, which comes from the keys
    fn calculate(&self, public_key: &dyn Params, output: &mut [u8]) -> Result<(), AlgoError> {
        let public_key = public_key
            .as_any()
            .downcast_ref::<A::PublicKey>()
            .ok_or(AlgoError::new(ErrorKind::InvalidParams))?;
        if output.len() < self.0.agreement_size() {
            return Err(AlgoError::new(ErrorKind::DataLength));
        }
        self.0
            .calculate_agreement(public_key, output)
            .map_err(|error| AlgoError::with_source(ErrorKind::InvalidParams, error))
    }
}

// Inits `agreement` with `params`; a failure comes from the private key, so it is InvalidParams
pub(super) fn init_with<P, A>(mut agreement: A, params: &P) -> Result<Box<dyn Inner>, AlgoError>
where
    A: AgreementInit<P> + tc_agreement::Agreement + 'static,
    A::PublicKey: Sized + 'static,
    <A as AgreementInit<P>>::Error: Error + Send + Sync + 'static,
    <A as tc_agreement::Agreement>::Error: Error + Send + Sync + 'static,
{
    agreement
        .init(params)
        .map_err(|error| AlgoError::with_source(ErrorKind::InvalidParams, error))?;
    Ok(Box::new(Typed(agreement)))
}

// Inits `agreement` with the params as a P; None when they are not a P
pub(super) fn init_as<P, A>(
    agreement: A,
    params: &dyn Params,
) -> Option<Result<Box<dyn Inner>, AlgoError>>
where
    P: 'static,
    A: AgreementInit<P> + tc_agreement::Agreement + 'static,
    A::PublicKey: Sized + 'static,
    <A as AgreementInit<P>>::Error: Error + Send + Sync + 'static,
    <A as tc_agreement::Agreement>::Error: Error + Send + Sync + 'static,
{
    let params = params.as_any().downcast_ref::<P>()?;
    Some(init_with(agreement, params))
}

// An agreement whose engine depends on the type of its params: init asks `init` for one, as the
// rows over EC keys try each curve type in turn
pub(super) struct Erased<F> {
    init: F,
    inner: Option<Box<dyn Inner>>,
}

impl<F> Erased<F>
where
    F: Fn(&dyn Params) -> Option<Result<Box<dyn Inner>, AlgoError>> + 'static,
{
    pub(super) fn boxed(init: F) -> Box<dyn Agreement> {
        Box::new(Self { init, inner: None })
    }
}

impl<F> tc_agreement::Agreement for Erased<F> {
    type PublicKey = dyn Params;
    type Error = AlgoError;

    // The length of the secret, or 0 before an init that succeeded
    fn agreement_size(&self) -> usize {
        self.inner
            .as_ref()
            .map_or(0, |inner| inner.agreement_size())
    }

    fn calculate_agreement(
        &self,
        public_key: &dyn Params,
        output: &mut [u8],
    ) -> Result<(), AlgoError> {
        self.inner
            .as_ref()
            .ok_or(AlgoError::new(ErrorKind::NotInitialized))?
            .calculate(public_key, output)
    }
}

impl<F> AgreementInit<dyn Params> for Erased<F>
where
    F: Fn(&dyn Params) -> Option<Result<Box<dyn Inner>, AlgoError>>,
{
    type Error = AlgoError;

    // Params of a type the row does not take are InvalidParams
    fn init(&mut self, params: &dyn Params) -> Result<(), AlgoError> {
        self.inner = None;
        let inner = (self.init)(params).ok_or(AlgoError::new(ErrorKind::InvalidParams))??;
        self.inner = Some(inner);
        Ok(())
    }
}

impl<F> Agreement for Erased<F> where
    F: Fn(&dyn Params) -> Option<Result<Box<dyn Inner>, AlgoError>> + 'static
{
}
