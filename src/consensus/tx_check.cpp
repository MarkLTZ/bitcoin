// Copyright (c) 2017-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/tx_check.h>

#include <primitives/transaction.h>
#include <consensus/validation.h>

bool CheckTransaction(const CTransaction& tx, TxValidationState& state)
{
    // Basic checks that don't depend on any context
    if (tx.vin.empty() && tx.vJoinSplit.empty() && tx.vShieldedSpend.empty())
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vin-empty");
    if (tx.vout.empty() && tx.vJoinSplit.empty() && tx.vShieldedOutput.empty())
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vout-empty");
    // Size limits (this doesn't take the witness into account, as that hasn't been checked for malleability)
    if (::GetSerializeSize(tx, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT)
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-oversize");

    // Check for negative or overflow output values (see CVE-2010-5139)
    CAmount nValueOut = 0;
    for (const auto& txout : tx.vout)
    {
        if (txout.nValue < 0)
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vout-negative");
        if (txout.nValue > MAX_MONEY)
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vout-toolarge");
        nValueOut += txout.nValue;
        if (!MoneyRange(nValueOut))
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-txouttotal-toolarge");
    }

    // Check for non-zero valueBalance when there are no Sapling inputs or outputs
    if (tx.vShieldedSpend.empty() && tx.vShieldedOutput.empty() && tx.valueBalance != 0)
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-valuebalance-nonzero");

    // Check for overflow valueBalance
    if (tx.valueBalance > MAX_MONEY || tx.valueBalance < -MAX_MONEY)
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-valuebalance-toolarge");

    if (tx.valueBalance <= 0) {
        // NB: negative valueBalance "takes" money from the transparent value pool just as outputs do
        nValueOut += -tx.valueBalance;

        if (!MoneyRange(nValueOut))
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-txouttotal-toolarge");
    }

    // Ensure that joinsplit values are well-formed
    for (const JSDescription& joinsplit : tx.vJoinSplit)
    {
        if (joinsplit.vpub_old < 0)
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vpub_old-negative");

        if (joinsplit.vpub_new < 0)
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vpub_new-negative");

        if (joinsplit.vpub_old > MAX_MONEY)
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vpub_old-toolarge");

        if (joinsplit.vpub_new > MAX_MONEY)
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vpub_new-toolarge");

        if (joinsplit.vpub_new != 0 && joinsplit.vpub_old != 0)
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vpubs-both-nonzero");

        nValueOut += joinsplit.vpub_old;
        if (!MoneyRange(nValueOut))
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-txouttotal-toolarge");
    }

    // Ensure input values do not exceed MAX_MONEY
    // We have not resolved the txin values at this stage,
    // but we do know what the joinsplits claim to add
    // to the value pool.
    CAmount nValueIn = 0;
    for (std::vector<JSDescription>::const_iterator it(tx.vJoinSplit.begin()); it != tx.vJoinSplit.end(); ++it)
    {
        nValueIn += it->vpub_new;

        if (!MoneyRange(it->vpub_new) || !MoneyRange(nValueIn))
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-txintotal-toolarge");
    }

    // Also check for Sapling
    if (tx.valueBalance >= 0) {
        // NB: positive valueBalance "adds" money to the transparent value pool, just as inputs do
        nValueIn += tx.valueBalance;

        if (!MoneyRange(nValueIn))
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-txintotal-toolarge");
    }

    // Check for duplicate inputs (see CVE-2018-17144)
    // While Consensus::CheckTxInputs does check if all inputs of a tx are available, and UpdateCoins marks all inputs
    // of a tx as spent, it does not check if the tx has duplicate inputs.
    // Failure to run this check will result in either a crash or an inflation bug, depending on the implementation of
    // the underlying coins database.
    std::set<COutPoint> vInOutPoints;
    for (const auto& txin : tx.vin) {
        if (!vInOutPoints.insert(txin.prevout).second)
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-inputs-duplicate");
    }

    // Check for duplicate joinsplit nullifiers in this transaction
    std::set<uint256> vInSproutNullifiers;
    for (const auto& joinsplit : tx.vJoinSplit) {
        for (const uint256& nf : joinsplit.nullifiers) {
            if (!vInSproutNullifiers.insert(nf).second)
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-joinsplits-nullifiers-duplicate");
        }
    }

    // Check for duplicate sapling nullifiers in this transaction
    std::set<uint256> vInSaplingNullifiers;
    for (const auto& spend_desc : tx.vShieldedSpend) {
        if (!vInSaplingNullifiers.insert(spend_desc.nullifier).second)
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-spend-description-nullifiers-duplicate");
    }

    if (tx.IsCoinBase())
    {
        if (tx.vin[0].scriptSig.size() < 2 || tx.vin[0].scriptSig.size() > 100)
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-cb-length");

        // A coinbase transaction cannot have spend descriptions
        if (tx.vShieldedSpend.size() > 0)
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-cb-has-spend-description");
    }
    else
    {
        for (const auto& txin : tx.vin)
            if (txin.prevout.IsNull())
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-prevout-null");

        for (const auto& spend_desc : tx.vShieldedSpend)
            if (spend_desc.nullifier.IsNull())
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-spend-description-nullifier-null");
    }

    return true;
}
