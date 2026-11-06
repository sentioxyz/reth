//! Sentio tracer support on top of evm2.

#[path = "expr.rs"]
mod expr;
#[path = "trace.rs"]
mod trace;

use alloy_consensus::{transaction::Recovered, Transaction};
use alloy_primitives::{keccak256, Address, Bytes, B256, B512, U256, U64};
use alloy_rpc_types_trace::geth::{
    sentio::{SentioReceipt, SentioTracerConfig},
    sentio_prestate::{
        AccountState as SentioAccountState, SentioPrestateResult, SentioPrestateTracerConfig,
    },
    GethDebugBuiltInTracerType, GethDebugTracerType, GethDebugTracingOptions, GethTrace,
    PreStateConfig, PreStateFrame, SentioDebugTracingOptions,
};
use evm2::{
    bytecode::Bytecode,
    env::BlockEnv,
    evm::DynDatabase,
    interpreter::{
        opcode::{op, OpCode},
        Gas, GasTracker, InstrStop, Interpreter, Message, MessageResult, MessageResultExt,
    },
    EvmTypes, EvmTypesHost, Inspector, TxResultWithState,
};
use evm2_inspectors::tracing::{
    types::CallTraceNode, DebugInspector as Evm2DebugInspector, TracingInspector,
    TracingInspectorConfig, TransactionContext,
};
use reth_errors::RethError;
use reth_rpc_eth_types::EthApiError;
use std::collections::BTreeMap;

use self::trace::SentioTraceBuilder;

#[derive(Clone, Debug)]
enum SentioTracerKind {
    Trace(SentioTracerConfig),
    Prestate(SentioPrestateTracerConfig),
    Raw,
}

#[derive(Debug)]
enum InspectorKind {
    Upstream(Evm2DebugInspector),
    Sentio(TracingInspector, SentioTracerKind),
}

/// Debug inspector that adds Sentio's tracers and execution overrides to evm2's built-ins.
#[derive(Debug)]
pub(super) struct DebugInspector {
    inner: InspectorKind,
    runtime: SentioRuntime,
}

#[derive(Debug, Default)]
struct SentioRuntime {
    config: SentioDebugTracingOptions,
    step_gas: Vec<Gas>,
}

impl DebugInspector {
    pub(super) fn new(opts: GethDebugTracingOptions) -> Result<Self, EthApiError> {
        let runtime = SentioRuntime { config: opts.sentio_config.clone(), step_gas: Vec::new() };
        let sentio_kind = match opts.tracer.as_ref() {
            Some(GethDebugTracerType::BuiltInTracer(GethDebugBuiltInTracerType::SentioTracer)) => {
                Some(SentioTracerKind::Trace(
                    opts.tracer_config
                        .clone()
                        .into_sentio_config()
                        .map_err(|_| EthApiError::InvalidTracerConfig)?,
                ))
            }
            Some(GethDebugTracerType::BuiltInTracer(
                GethDebugBuiltInTracerType::SentioPrestateTracer,
            )) => Some(SentioTracerKind::Prestate(
                opts.tracer_config
                    .clone()
                    .into_sentio_prestate_config()
                    .map_err(|_| EthApiError::InvalidTracerConfig)?,
            )),
            Some(GethDebugTracerType::BuiltInTracer(
                GethDebugBuiltInTracerType::SentioRethRawTracer,
            )) => Some(SentioTracerKind::Raw),
            _ => None,
        };

        let inner = if let Some(kind) = sentio_kind {
            let config = TracingInspectorConfig {
                record_inputs: true,
                record_memory_snapshots: true,
                record_logs: true,
                ..TracingInspectorConfig::default_geth()
            };
            InspectorKind::Sentio(TracingInspector::new(config), kind)
        } else {
            InspectorKind::Upstream(Evm2DebugInspector::new(opts).map_err(EthApiError::from)?)
        };
        Ok(Self { inner, runtime })
    }

    pub(super) fn fuse(&mut self) -> Result<(), EthApiError> {
        self.runtime.step_gas.clear();
        match &mut self.inner {
            InspectorKind::Upstream(inspector) => inspector.fuse().map_err(EthApiError::from),
            InspectorKind::Sentio(inspector, _) => {
                inspector.fuse();
                Ok(())
            }
        }
    }

    pub(super) fn get_result<T: EvmTypesHost<Tx: Transaction>>(
        &mut self,
        tx_context: Option<TransactionContext>,
        tx: &Recovered<T::Tx>,
        block_env: &BlockEnv<T>,
        res: &TxResultWithState<T>,
        db: &mut dyn DynDatabase,
    ) -> Result<GethTrace, EthApiError> {
        match &mut self.inner {
            InspectorKind::Upstream(inspector) => {
                inspector.get_result(tx_context, tx, block_env, res, db).map_err(EthApiError::from)
            }
            InspectorKind::Sentio(inspector, kind) => {
                inspector.set_transaction_gas_limit(tx.gas_limit());
                let nodes = inspector.clone().into_traces().into_nodes();
                match kind {
                    SentioTracerKind::Trace(config) => {
                        let receipt = SentioReceipt {
                            nonce: Some(tx.nonce()),
                            tx_hash: tx_context.as_ref().and_then(|ctx| ctx.tx_hash),
                            block_number: Some(U64::from(block_env.number.saturating_to::<u64>())),
                            block_hash: tx_context.as_ref().and_then(|ctx| ctx.block_hash),
                            transaction_index: tx_context
                                .as_ref()
                                .and_then(|ctx| ctx.tx_index)
                                .map(|index| index as u64),
                            gas_price: Some(U256::from(
                                tx.effective_gas_price(Some(block_env.basefee.saturating_to())),
                            )),
                        };
                        let origin = self.runtime.config.tx_origin_override().or(Some(tx.signer()));
                        Ok(SentioTraceBuilder::new(nodes, origin, config.clone())
                            .sentio_traces(
                                res.result.tx_gas_used(),
                                res.result.final_refunded(),
                                Some(receipt),
                            )
                            .into())
                    }
                    SentioTracerKind::Prestate(config) => {
                        let standard = inspector
                            .geth_builder()
                            .geth_prestate_traces(
                                res,
                                &PreStateConfig {
                                    diff_mode: Some(config.diff_mode),
                                    ..Default::default()
                                },
                                db,
                            )
                            .map_err(|err| EthApiError::Internal(RethError::other(err)))?;
                        Ok(sentio_prestate(standard, &nodes).into())
                    }
                    SentioTracerKind::Raw => {
                        let value = serde_json::to_value(nodes)
                            .map_err(|err| EthApiError::Internal(RethError::other(err)))?;
                        Ok(GethTrace::SentioRethRawTracer(value))
                    }
                }
            }
        }
    }

    #[cfg(feature = "js-tracer")]
    pub(super) fn with_js_interrupt(
        mut self,
        interrupt: evm2_inspectors::tracing::js::JsInspectorInterrupt,
    ) -> Self {
        if let InspectorKind::Upstream(Evm2DebugInspector::Js(js)) = self.inner {
            self.inner = InspectorKind::Upstream(Evm2DebugInspector::Js(Box::new(
                js.with_interrupt(interrupt),
            )));
        }
        self
    }

    fn delegate<T: EvmTypes, R>(&mut self, f: impl FnOnce(&mut dyn Inspector<T>) -> R) -> R {
        match &mut self.inner {
            InspectorKind::Upstream(inspector) => f(inspector),
            InspectorKind::Sentio(inspector, _) => f(inspector),
        }
    }
}

impl SentioRuntime {
    fn before_step<T: EvmTypes>(&mut self, interp: &mut Interpreter<'_, '_, T>) {
        if self.config.ignore_gas_cost() {
            self.step_gas.push(interp.gas());
            let gas = interp.gas_mut();
            gas.set_limit(u64::MAX);
            gas.set_remaining(u64::MAX);
            gas.set_reservoir(u64::MAX);
        }
    }

    fn after_step<T: EvmTypes>(&mut self, interp: &mut Interpreter<'_, '_, T>) {
        match interp.opcode() {
            op::ORIGIN => {
                if let Some(address) = self.config.tx_origin_override() {
                    set_stack_top(interp, address);
                }
            }
            op::CALLER => {
                let message = interp.message();
                if let Some(selector) = selector(&message.input) &&
                    let Some(address) =
                        self.config.get_caller_override(message.destination, selector)
                {
                    set_stack_top(interp, address);
                }
            }
            _ => {}
        }
        if self.config.ignore_gas_cost() &&
            let Some(gas) = self.step_gas.pop()
        {
            interp.set_gas(gas);
        }
    }

    fn prepare_call<T: EvmTypes>(&self, message: &mut Message<T>) -> Option<MessageResult<T>> {
        if self.config.ignore_gas_cost() {
            // Message gas is constructed while the parent opcode temporarily has unlimited gas.
            // Cap it to the parent's real pre-op budget; individual child opcodes are made free.
            if let Some(parent) = self.step_gas.last() {
                message.gas_limit = message.gas_limit.min(parent.remaining());
            }
        }
        let selector = selector(&message.input)?;
        self.config.get_mock_function(message.destination, selector).map(|output| {
            MessageResultExt {
                stop: InstrStop::Return,
                gas: GasTracker::new(message.gas_limit),
                output,
                created_address: None,
                ext: Default::default(),
                _non_exhaustive: (),
            }
        })
    }

    fn prepare_create<T: EvmTypes>(&self, message: &mut Message<T>) {
        let original = message.destination;
        if let Some(address) = self.config.creation_address_override() {
            set_create_destination::<T>(message, address);
        }
        if let Some(creation_override) = self.config.get_creation_override(original) {
            if let Some(address) = creation_override.new_address {
                set_create_destination::<T>(message, address);
            }
            if let Some(code) = creation_override.new_code.clone() {
                message.input = code.clone();
                message.code = Bytecode::new_legacy(code);
            }
        }
    }
}

fn set_create_destination<T: EvmTypes>(message: &mut Message<T>, address: Address) {
    message.destination = address;
    message.call_target = address;
    message.code_address = address;
}

fn selector(input: &Bytes) -> Option<alloy_primitives::Selector> {
    (input.len() >= 4).then(|| alloy_primitives::Selector::from_slice(&input[..4]))
}

fn set_stack_top<T: EvmTypes>(interp: &mut Interpreter<'_, '_, T>, address: Address) {
    if let Some(top) = interp.stack_mut().as_slice_mut().last_mut() {
        *top = U256::from_be_slice(address.as_slice());
    }
}

impl<T: EvmTypes> Inspector<T> for DebugInspector {
    fn initialize_interp(&mut self, interp: &mut Interpreter<'_, '_, T>) {
        self.delegate::<T, _>(|inspector| inspector.initialize_interp(interp))
    }

    fn step(&mut self, interp: &mut Interpreter<'_, '_, T>) {
        self.delegate::<T, _>(|inspector| inspector.step(interp));
        self.runtime.before_step(interp);
    }

    fn step_end(&mut self, interp: &mut Interpreter<'_, '_, T>) {
        self.runtime.after_step(interp);
        self.delegate::<T, _>(|inspector| inspector.step_end(interp));
    }

    fn log(&mut self, log: &alloy_primitives::Log, host: &mut T::Host<'_>) {
        self.delegate::<T, _>(|inspector| inspector.log(log, host))
    }

    fn call(
        &mut self,
        interp: &mut Interpreter<'_, '_, T>,
        message: &mut Message<T>,
    ) -> Option<MessageResult<T>> {
        let mocked = self.runtime.prepare_call::<T>(message);
        self.delegate::<T, _>(|inspector| inspector.call(interp, message)).or(mocked)
    }

    fn call_end(
        &mut self,
        interp: &mut Interpreter<'_, '_, T>,
        message: &Message<T>,
        result: &mut MessageResult<T>,
    ) {
        self.delegate::<T, _>(|inspector| inspector.call_end(interp, message, result))
    }

    fn create(
        &mut self,
        interp: &mut Interpreter<'_, '_, T>,
        message: &mut Message<T>,
    ) -> Option<MessageResult<T>> {
        self.runtime.prepare_create::<T>(message);
        self.delegate::<T, _>(|inspector| inspector.create(interp, message))
    }

    fn create_end(
        &mut self,
        interp: &mut Interpreter<'_, '_, T>,
        message: &Message<T>,
        result: &mut MessageResult<T>,
    ) {
        self.delegate::<T, _>(|inspector| inspector.create_end(interp, message, result))
    }

    fn selfdestruct(
        &mut self,
        contract: &Address,
        target: &Address,
        value: &U256,
        host: &mut T::Host<'_>,
    ) {
        self.delegate::<T, _>(|inspector| inspector.selfdestruct(contract, target, value, host))
    }
}

fn sentio_account(account: alloy_rpc_types_trace::geth::AccountState) -> SentioAccountState {
    SentioAccountState {
        balance: account.balance,
        code: account.code,
        nonce: account.nonce,
        storage: account.storage,
        ..Default::default()
    }
}

fn sentio_state(
    state: BTreeMap<Address, alloy_rpc_types_trace::geth::AccountState>,
) -> BTreeMap<Address, SentioAccountState> {
    state.into_iter().map(|(address, account)| (address, sentio_account(account))).collect()
}

fn sentio_prestate(frame: PreStateFrame, nodes: &[CallTraceNode]) -> SentioPrestateResult {
    let mut result = match frame {
        PreStateFrame::Default(mode) => {
            SentioPrestateResult { pre: sentio_state(mode.0), post: None }
        }
        PreStateFrame::Diff(mode) => SentioPrestateResult {
            pre: sentio_state(mode.pre),
            post: Some(sentio_state(mode.post)),
        },
    };

    for node in nodes {
        for step in &node.trace.steps {
            let Some(stack) = &step.stack else { continue };
            let address = node.execution_address();
            let code_address = node.trace.address;
            match step.op {
                OpCode::SLOAD | OpCode::SSTORE => {
                    if let Some(entry) = result.pre.get_mut(&address) &&
                        let Some(slot) = stack.last()
                    {
                        let slot = B256::from(slot.to_be_bytes());
                        entry.code_address = Some(code_address);
                        entry.code_address_by_slot.insert(slot, code_address);
                    }
                }
                OpCode::KECCAK256 => {
                    let Some(entry) = result.pre.get_mut(&address) else { continue };
                    let Some(memory) = &step.memory else { continue };
                    if stack.len() < 2 {
                        continue
                    }
                    let offset = stack[stack.len() - 1].to::<usize>();
                    let size = stack[stack.len() - 2].to::<usize>();
                    if size != 64 || offset.saturating_add(size) > memory.len() {
                        continue
                    }
                    let raw_key = &memory.as_bytes()[offset..offset + size];
                    let hash_of_key = keccak256(raw_key);
                    entry.mapping_keys.insert(B512::from_slice(raw_key), hash_of_key);
                    let base_slot = B256::from_slice(&raw_key[32..]);
                    entry.code_address_by_slot.insert(base_slot, code_address);
                    entry.code_address_by_slot.insert(hash_of_key, code_address);
                }
                _ => {}
            }
        }
    }
    if let Some(post) = &mut result.post {
        for (address, state) in &result.pre {
            post.entry(*address).or_default().mapping_keys = state.mapping_keys.clone();
        }
    }
    result
}
