#![cfg_attr(not(test), warn(unused_crate_dependencies))]

use std::sync::Arc;

use alloy_genesis::Genesis;
use alloy_network::{AnyNetwork, TransactionBuilder};
use alloy_primitives::{hex, Address, TxKind};
use alloy_rpc_types_trace::geth::sentio::{FunctionInfo, SentioTracerConfig};
use alloy_rpc_types_trace::geth::{GethDebugBuiltInTracerType, GethDebugTracerConfig, GethDebugTracerType, GethDebugTracingCallOptions, GethDebugTracingOptions, GethTrace};
use futures_util::StreamExt;
use reth::primitives::revm_primitives::ruint::aliases::U256;
use reth::primitives::{Account, BlockId, BlockNumberOrTag};
use reth::providers::DatabaseProviderFactory;
use reth::rpc::api::eth::helpers::{Call, EthTransactions};
use reth::rpc::api::eth::RpcReceipt;
use reth::rpc::api::EthApiServer;
use reth::rpc::types::{TransactionInput, TransactionRequest};
use reth::{
    builder::{NodeBuilder, NodeHandle},
    providers::CanonStateSubscriptions,
    tasks::TaskManager,
};
use reth_chainspec::ChainSpec;
use reth_db::tables;
use reth_db::test_utils::create_test_rw_db;
use reth_db::transaction::DbTxMut;
use reth_node_core::args::DevArgs;
use reth_node_core::{args::RpcServerArgs, node_config::NodeConfig};
use reth_node_ethereum::EthereumNode;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let tasks = TaskManager::current();

    // create node config
    let node_config = NodeConfig::test()
        .with_dev(DevArgs {
            dev: true,
            block_max_transactions: Some(1),
            block_time: None,
        })
        .with_rpc(RpcServerArgs::default().with_http())
        .with_chain(custom_chain());

    let db = create_test_rw_db();
    let NodeHandle { node, node_exit_future: _ } = NodeBuilder::new(node_config)
        .with_database(db)
        .testing_node(tasks.executor())
        .node(EthereumNode::default())
        .launch()
        .await?;

    let eth_api = node.rpc_registry.eth_api();
    let debug_api = node.rpc_registry.debug_api();
    let mut notifications = node.provider.canonical_state_stream();

    // prepare dev accounts
    let dev_accounts = eth_api.accounts()?;
    let user1 = dev_accounts[0];
    // let user2 = dev_accounts[1];

    let db = node.provider.database_provider_rw()?;
    let tx = db.tx_ref();
    tx.put::<tables::PlainAccountState>(user1, Account {
        balance: U256::from(100000000000000_u64),
        ..Default::default()
    })?;
    db.commit()?;

    // create weth
    let weth_code = hex!("60606040526040805190810160405280600d81526020017f57726170706564204574686572000000000000000000000000000000000000008152506000908051906020019061004f9291906100c8565b506040805190810160405280600481526020017f57455448000000000000000000000000000000000000000000000000000000008152506001908051906020019061009b9291906100c8565b506012600260006101000a81548160ff021916908360ff16021790555034156100c357600080fd5b61016d565b828054600181600116156101000203166002900490600052602060002090601f016020900481019282601f1061010957805160ff1916838001178555610137565b82800160010185558215610137579182015b8281111561013657825182559160200191906001019061011b565b5b5090506101449190610148565b5090565b61016a91905b8082111561016657600081600090555060010161014e565b5090565b90565b610c348061017c6000396000f3006060604052600436106100af576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff16806306fdde03146100b9578063095ea7b31461014757806318160ddd146101a157806323b872dd146101ca5780632e1a7d4d14610243578063313ce5671461026657806370a082311461029557806395d89b41146102e2578063a9059cbb14610370578063d0e30db0146103ca578063dd62ed3e146103d4575b6100b7610440565b005b34156100c457600080fd5b6100cc6104dd565b6040518080602001828103825283818151815260200191508051906020019080838360005b8381101561010c5780820151818401526020810190506100f1565b50505050905090810190601f1680156101395780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b341561015257600080fd5b610187600480803573ffffffffffffffffffffffffffffffffffffffff1690602001909190803590602001909190505061057b565b604051808215151515815260200191505060405180910390f35b34156101ac57600080fd5b6101b461066d565b6040518082815260200191505060405180910390f35b34156101d557600080fd5b610229600480803573ffffffffffffffffffffffffffffffffffffffff1690602001909190803573ffffffffffffffffffffffffffffffffffffffff1690602001909190803590602001909190505061068c565b604051808215151515815260200191505060405180910390f35b341561024e57600080fd5b61026460048080359060200190919050506109d9565b005b341561027157600080fd5b610279610b05565b604051808260ff1660ff16815260200191505060405180910390f35b34156102a057600080fd5b6102cc600480803573ffffffffffffffffffffffffffffffffffffffff16906020019091905050610b18565b6040518082815260200191505060405180910390f35b34156102ed57600080fd5b6102f5610b30565b6040518080602001828103825283818151815260200191508051906020019080838360005b8381101561033557808201518184015260208101905061031a565b50505050905090810190601f1680156103625780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b341561037b57600080fd5b6103b0600480803573ffffffffffffffffffffffffffffffffffffffff16906020019091908035906020019091905050610bce565b604051808215151515815260200191505060405180910390f35b6103d2610440565b005b34156103df57600080fd5b61042a600480803573ffffffffffffffffffffffffffffffffffffffff1690602001909190803573ffffffffffffffffffffffffffffffffffffffff16906020019091905050610be3565b6040518082815260200191505060405180910390f35b34600360003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600082825401925050819055503373ffffffffffffffffffffffffffffffffffffffff167fe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c346040518082815260200191505060405180910390a2565b60008054600181600116156101000203166002900480601f0160208091040260200160405190810160405280929190818152602001828054600181600116156101000203166002900480156105735780601f1061054857610100808354040283529160200191610573565b820191906000526020600020905b81548152906001019060200180831161055657829003601f168201915b505050505081565b600081600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055508273ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff167f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925846040518082815260200191505060405180910390a36001905092915050565b60003073ffffffffffffffffffffffffffffffffffffffff1631905090565b600081600360008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054101515156106dc57600080fd5b3373ffffffffffffffffffffffffffffffffffffffff168473ffffffffffffffffffffffffffffffffffffffff16141580156107b457507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff600460008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205414155b156108cf5781600460008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020541015151561084457600080fd5b81600460008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600082825403925050819055505b81600360008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000828254039250508190555081600360008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600082825401925050819055508273ffffffffffffffffffffffffffffffffffffffff168473ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef846040518082815260200191505060405180910390a3600190509392505050565b80600360003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205410151515610a2757600080fd5b80600360003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600082825403925050819055503373ffffffffffffffffffffffffffffffffffffffff166108fc829081150290604051600060405180830381858888f193505050501515610ab457600080fd5b3373ffffffffffffffffffffffffffffffffffffffff167f7fcf532c15f0a6db0bd6d0e038bea71d30d808c7d98cb3bf7268a95bf5081b65826040518082815260200191505060405180910390a250565b600260009054906101000a900460ff1681565b60036020528060005260406000206000915090505481565b60018054600181600116156101000203166002900480601f016020809104026020016040519081016040528092919081815260200182805460018160011615610100020316600290048015610bc65780601f10610b9b57610100808354040283529160200191610bc6565b820191906000526020600020905b815481529060010190602001808311610ba957829003601f168201915b505050505081565b6000610bdb33848461068c565b905092915050565b60046020528160005260406000206020528060005260406000206000915091505054815600a165627a7a72305820deb4c2ccab3c2fdca32ab3f46728389c2fe2c165d5fafa07661e4e004f6c344a0029");
    let hash = EthTransactions::send_transaction(eth_api, TransactionRequest {
        from: Some(user1),
        to: Some(TxKind::Create),
        input: TransactionInput {
            data: Some(weth_code.into()),
            ..Default::default()
        },
        gas: Some(10000000_u64),
        gas_price: Some(100_u128),
        ..Default::default()
    }).await?;
    let head = notifications.next().await.unwrap();
    let tx = head.tip().transactions().next().unwrap();
    assert_eq!(tx.hash, hash);

    let receipt: RpcReceipt<AnyNetwork> = EthTransactions::transaction_receipt(eth_api, hash).await?.unwrap();
    let weth_addr = receipt.contract_address.unwrap();
    // println!("created weth: {:?}", weth_addr);

    // prepare tracer config
    let sentio_tracer_config = build_sentio_tracer_config(weth_addr);
    let tracing_opt = GethDebugTracingOptions {
        tracer: Some(GethDebugTracerType::BuiltInTracer(GethDebugBuiltInTracerType::SentioTracer)),
        tracer_config: GethDebugTracerConfig(serde_json::to_value(sentio_tracer_config)?),
        ..Default::default()
    };

    // deposit some eth
    let hash = EthTransactions::send_transaction(eth_api, TransactionRequest {
        from: Some(user1),
        to: Some(TxKind::Call(weth_addr)),
        value: Some(U256::from(1000)),
        gas: Some(10000000_u64),
        gas_price: Some(100_u128),
        ..Default::default()
    }).await?;
    let head = notifications.next().await.unwrap();
    let tx = head.tip().transactions().next().unwrap();
    assert_eq!(tx.hash, hash);

    let GethTrace::SentioTracer(trace) = debug_api.debug_trace_transaction(hash, tracing_opt.clone()).await? else {
        return Err(eyre::eyre!("no trace found"));
    };
    assert_eq!(trace.traces[0].typ, "JUMP");
    assert_eq!(trace.traces[0].name, Some("deposit".to_string()));
    assert_eq!(trace.traces[0].traces[0].typ, "LOG2");

    // transfer weth
    let mut request = TransactionRequest {
        from: Some(user1),
        to: Some(TxKind::Call(weth_addr)),
        gas: Some(10000000_u64),
        gas_price: Some(100_u128),
        input: TransactionInput {
            input: Some(hex::decode("a9059cbb00000000000000000000000000000000000000000000000000000000000004560000000000000000000000000000000000000000000000000000000000000064").unwrap().into()),
            data: None,
        },
        ..Default::default()
    };
    let estimated_gas = eth_api.estimate_gas_at(request.clone(), BlockId::pending(), None).await?;
    let gas_limit = estimated_gas;
    request.set_gas_limit(gas_limit.to());

    let hash = EthTransactions::send_transaction(eth_api, request.clone()).await?;
    let head = notifications.next().await.unwrap();
    let tx = head.tip().transactions().next().unwrap();
    assert_eq!(tx.hash, hash);

    let GethTrace::SentioTracer(trace) = debug_api.debug_trace_transaction(hash, tracing_opt.clone()).await? else {
        return Err(eyre::eyre!("no trace found"));
    };
    assert_eq!(trace.pc, 880);
    assert_eq!(trace.start_index, 60);
    assert_eq!(trace.end_index, 273);
    assert_eq!(trace.traces[0].typ, "JUMP");
    assert_eq!(trace.traces[0].name, Some("transferFrom".to_string()));
    assert_eq!(trace.traces[0].input_stack.as_ref().unwrap().len(), 3);
    assert_eq!(trace.traces[0].output_stack.as_ref().unwrap().len(), 1);
    assert_eq!(trace.traces[0].traces[0].typ, "LOG3");

    // debug_traceCall
    let bn = u64::from(eth_api.block_number()?.byte(0)) - 1;
    let block_id = BlockId::Number(BlockNumberOrTag::Number(bn));
    let opt = GethDebugTracingCallOptions {
        tracing_options: tracing_opt,
        ..Default::default()
    };
    let GethTrace::SentioTracer(mut trace_call_trace) = debug_api.debug_trace_call(request, Some(block_id), opt).await? else {
        return Err(eyre::eyre!("no trace found"));
    };
    trace_call_trace.receipt = trace.receipt.clone(); // ignore in comparing
    assert_eq!(trace, trace_call_trace);

    Ok(())
}

fn build_sentio_tracer_config(weth_addr: Address) -> SentioTracerConfig {
    let functions_str = r#"[{"name":"approve","signatureHash":"0x095ea7b3","pc":327,"inputSize":2,"inputMemory":false,"outputSize":1,"outputMemory":false},{"name":"approve","signatureHash":"0x095ea7b3","pc":338,"inputSize":2,"inputMemory":false,"outputSize":1,"outputMemory":false},{"name":"approve","signatureHash":"0x095ea7b3","pc":391,"inputSize":2,"inputMemory":false,"outputSize":1,"outputMemory":false},{"name":"totalSupply","signatureHash":"0x18160ddd","pc":417,"inputSize":0,"inputMemory":false,"outputSize":1,"outputMemory":false},{"name":"totalSupply","signatureHash":"0x18160ddd","pc":428,"inputSize":0,"inputMemory":false,"outputSize":1,"outputMemory":false},{"name":"totalSupply","signatureHash":"0x18160ddd","pc":436,"inputSize":0,"inputMemory":false,"outputSize":1,"outputMemory":false},{"name":"transferFrom","signatureHash":"0x23b872dd","pc":458,"inputSize":3,"inputMemory":false,"outputSize":1,"outputMemory":false},{"name":"transferFrom","signatureHash":"0x23b872dd","pc":469,"inputSize":3,"inputMemory":false,"outputSize":1,"outputMemory":false},{"name":"transferFrom","signatureHash":"0x23b872dd","pc":553,"inputSize":3,"inputMemory":false,"outputSize":1,"outputMemory":false},{"name":"withdraw","signatureHash":"0x2e1a7d4d","pc":579,"inputSize":1,"inputMemory":false,"outputSize":0,"outputMemory":false},{"name":"withdraw","signatureHash":"0x2e1a7d4d","pc":590,"inputSize":1,"inputMemory":false,"outputSize":0,"outputMemory":false},{"name":"withdraw","signatureHash":"0x2e1a7d4d","pc":612,"inputSize":1,"inputMemory":false,"outputSize":0,"outputMemory":false},{"name":"transfer","signatureHash":"0xa9059cbb","pc":880,"inputSize":2,"inputMemory":false,"outputSize":1,"outputMemory":false},{"name":"transfer","signatureHash":"0xa9059cbb","pc":891,"inputSize":2,"inputMemory":false,"outputSize":1,"outputMemory":false},{"name":"transfer","signatureHash":"0xa9059cbb","pc":944,"inputSize":2,"inputMemory":false,"outputSize":1,"outputMemory":false},{"name":"deposit","signatureHash":"0xd0e30db0","pc":970,"inputSize":0,"inputMemory":false,"outputSize":0,"outputMemory":false},{"name":"deposit","signatureHash":"0xd0e30db0","pc":978,"inputSize":0,"inputMemory":false,"outputSize":0,"outputMemory":false},{"name":"deposit","signatureHash":"0xd0e30db0","pc":1088,"inputSize":0,"inputMemory":false,"outputSize":0,"outputMemory":false},{"name":"approve","signatureHash":"0x095ea7b3","pc":1403,"inputSize":2,"inputMemory":false,"outputSize":1,"outputMemory":false},{"name":"totalSupply","signatureHash":"0x18160ddd","pc":1645,"inputSize":0,"inputMemory":false,"outputSize":1,"outputMemory":false},{"name":"transferFrom","signatureHash":"0x23b872dd","pc":1676,"inputSize":3,"inputMemory":false,"outputSize":1,"outputMemory":false},{"name":"withdraw","signatureHash":"0x2e1a7d4d","pc":2521,"inputSize":1,"inputMemory":false,"outputSize":0,"outputMemory":false},{"name":"transfer","signatureHash":"0xa9059cbb","pc":3022,"inputSize":2,"inputMemory":false,"outputSize":1,"outputMemory":false}]"#;
    let mut tracer_cfg: SentioTracerConfig = Default::default();
    let functions: Vec<FunctionInfo> = serde_json::from_str(functions_str).unwrap();
    tracer_cfg.with_internal_calls = true;
    tracer_cfg.debug = true;
    tracer_cfg.functions.insert(weth_addr, functions);
    tracer_cfg.calls.insert(weth_addr, vec![182, 3034]);
    tracer_cfg
}

fn custom_chain() -> Arc<ChainSpec> {
    let custom_genesis = r#"
{
    "nonce": "0x42",
    "timestamp": "0x0",
    "extraData": "0x5343",
    "gasLimit": "0x1388000",
    "baseFeePerGas": "0x0",
    "difficulty": "0x400000000",
    "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "coinbase": "0x0000000000000000000000000000000000000000",
    "alloc": {
        "0x0000000000000000000000000000000000000123": {
            "balance": "0x4a47e3c12448f4ad000000"
        },
        "0x6Be02d1d3665660d22FF9624b7BE0551ee1Ac91b": {
            "balance": "0x4a47e3c12448f4ad000000"
        }
    },
    "number": "0x0",
    "gasUsed": "0x0",
    "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "config": {
        "ethash": {},
        "chainId": 2600,
        "homesteadBlock": 0,
        "eip150Block": 0,
        "eip155Block": 0,
        "eip158Block": 0,
        "byzantiumBlock": 0,
        "constantinopleBlock": 0,
        "petersburgBlock": 0,
        "istanbulBlock": 0,
        "berlinBlock": 0,
        "londonBlock": 0,
        "terminalTotalDifficulty": 0,
        "terminalTotalDifficultyPassed": true,
        "shanghaiTime": 0
    }
}
"#;
    let genesis: Genesis = serde_json::from_str(custom_genesis).unwrap();
    let mut chain_spec = ChainSpec::from(genesis);
    chain_spec.paris_block_and_final_difficulty = Some((0, U256::from(0)));
    Arc::new(chain_spec)
}
