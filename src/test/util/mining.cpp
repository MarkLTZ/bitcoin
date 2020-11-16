// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/mining.h>

#include <chainparams.h>
#include <consensus/merkle.h>
#include <crypto/equihash.h>
#include <key_io.h>
#include <miner.h>
#include <node/context.h>
#include <pow.h>
#include <script/standard.h>
#include <validation.h>

CTxIn generatetoaddress(const NodeContext& node, const std::string& address)
{
    const auto dest = DecodeDestination(address);
    assert(IsValidDestination(dest));
    const auto coinbase_script = GetScriptForDestination(dest);

    return MineBlock(node, coinbase_script);
}

CTxIn MineBlock(const NodeContext& node, const CScript& coinbase_scriptPubKey)
{
    const CChainParams& chainparams = Params();

    static const int nInnerLoopCount = 0xFFFF;
    static const int nInnerLoopMask = 0xFFFF;
    uint64_t nMaxTries = 1000000;

    unsigned n = chainparams.GetConsensus().EquihashN(::ChainActive().Tip()->nHeight + 1);
    unsigned k = chainparams.GetConsensus().EquihashK(::ChainActive().Tip()->nHeight + 1);

    auto block = PrepareBlock(node, coinbase_scriptPubKey);

    crypto_generichash_blake2b_state eh_state;
    EhInitialiseState(n, k, eh_state);

    // I = the block header minus nonce and solution.
    CEquihashInput I{*block};
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << I;

    // H(I||...
    crypto_generichash_blake2b_update(&eh_state, (unsigned char*)&ss[0], ss.size());

    while (nMaxTries > 0 && ((int)block->nNonce.GetUint64(0) & nInnerLoopMask) < nInnerLoopCount) {
        // Yes, there is a chance every nonce could fail to satisfy the -regtest
        // target -- 1 in 2^(2^256). That ain't gonna happen
        block->nNonce = ArithToUint256(UintToArith256(block->nNonce) + 1);

        // H(I||V||...
        crypto_generichash_blake2b_state curr_state;
        curr_state = eh_state;
        crypto_generichash_blake2b_update(&curr_state, block->nNonce.begin(), block->nNonce.size());

        // (x_1, x_2, ...) = A(I, V, n, k)
        std::function<bool(std::vector<unsigned char>)> validBlock =
                [&block](std::vector<unsigned char> soln) {
            block->nSolution = soln;
            return CheckProofOfWork(block->GetHash(), block->nBits, Params().GetConsensus());
        };
        bool found = EhBasicSolveUncancellable(n, k, curr_state, validBlock);
        --nMaxTries;
        if (found) {
            break;
        }
    }

    bool processed{ProcessNewBlock(Params(), block, true, nullptr)};
    assert(processed);

    return CTxIn{block->vtx[0]->GetHash(), 0};
}

std::shared_ptr<CBlock> PrepareBlock(const NodeContext& node, const CScript& coinbase_scriptPubKey)
{
    assert(node.mempool);
    auto block = std::make_shared<CBlock>(
        BlockAssembler{*node.mempool, Params()}
            .CreateNewBlock(coinbase_scriptPubKey)
            ->block);

    LOCK(cs_main);
    block->nTime = ::ChainActive().Tip()->GetMedianTimePast() + 1;
    block->hashMerkleRoot = BlockMerkleRoot(*block);

    return block;
}
