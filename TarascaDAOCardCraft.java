package org.tarasca.ardor.contracts;

import nxt.Nxt;
import nxt.addons.*;
import nxt.crypto.Crypto;

import nxt.http.responses.TransactionResponse;

import nxt.util.Convert;
import nxt.util.Logger;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import java.util.*;

import org.json.simple.JSONArray;

public class TarascaDAOCardCraft extends AbstractContract {

    TransactionContext transactionContext;

    private static final TreeMap<String, Integer> invalidationCache =  new TreeMap<>();
    private static final TreeMap<Long, Integer> assetDecimalCache =  new TreeMap<>();

    private static final int transactionDeadline = 1440;

    SecureRandom random;

    private long feeRateNQTPerFXT = 0;

    JO transactionMessageJO = new JO();

    private long senderBalanceNQT = 0;
    private long totalCostNQT = 0;

    String secretForRandomSerialString;
    byte[] privateKey;
    String adminPasswordString;

    public static class ApplicationTransactions {
        public TreeSet<String> transactionHashListFiltered = new TreeSet<>();
        public TreeSet<String> transactionHashListSpent = new TreeSet<>();
        public TreeMap<String, JO> transactionCache = new TreeMap<>();
        public TreeMap<String, JO> transactionListPayments = new TreeMap<>();

        public int ecBlockHeight = 0;
        public long ecBlockId = 0;
        public int timeStamp = 0;

        public void putPaymentTransaction(JO transactionJO) {
            String fullHash = transactionJO.getString("fullHash");

            if(!transactionListPayments.containsKey(fullHash)) {
                transactionListPayments.put(fullHash, transactionJO);

                int height = transactionJO.getInt("height");

                if(ecBlockHeight < height) {
                    ecBlockHeight = height;

                    JO response = nxt.http.callers.GetBlockCall.create().height(ecBlockHeight).call();

                    ecBlockId = Convert.parseUnsignedLong(response.getString("block"));
                    timeStamp = response.getInt("timestamp");
                }
            }
        }

        public void updateEcBlock(TransactionContext context) {
            TransactionResponse triggerTransaction = context.getTransaction();

            if(ecBlockHeight == triggerTransaction.getHeight()) {
                long contextEcBlockId = context.getBlock().getBlockId();

                // overwrite getExecutedTransactions that may return stale block on fork change

                if(ecBlockId != contextEcBlockId) {
                    context.logInfoMessage("ecBlockId : " + ecBlockId + " replaced with : " + contextEcBlockId);

                    ecBlockId = contextEcBlockId;
                    timeStamp = context.getBlock().getTimestamp();
                }
            }
        }
    }

    @ValidateContractRunnerIsRecipient
    public JO processTransaction(TransactionContext context) {

        transactionContext = context;
        JO params = context.getContractRunnerConfigParams(getClass().getSimpleName());

        int chainId = 2;

        {
            // bypass to allow explicit transaction deadline etc. until there is a standard way to override all default transaction parameters.

            String privateKeyHexString = params.getString("privateKey");

            if (privateKeyHexString == null || privateKeyHexString.length() != 0x40)
                return new JO(); // contract not yet configured

            privateKey = context.parseHexString(privateKeyHexString);
        }

        adminPasswordString = params.getString("adminPassword");

        if(adminPasswordString == null || adminPasswordString.equals("")) {
            transactionContext.logInfoMessage("contract requires admin password (adminPassword)");
            return new JO();
        }

        JA jsonTierArray = params.getArray("tieredAssetIds");
        JA jsonTierPromotionCostArray = params.getArray("tierPromotionCost");
        long assetCountForPromotion = Convert.parseUnsignedLong(params.getString("tierPromotionRequiredCount"));
        boolean requireIdenticalPerPromotion = params.getBoolean("requireIdenticalPerPromotion");

        JA paymentAccountArray = params.getArray("paymentAccountRS");
        JA paymentAccountFractionArray = params.getArray("paymentFractionFloat");

        if(paymentAccountArray == null || paymentAccountFractionArray == null) {
            paymentAccountArray = null;
            paymentAccountFractionArray = null;
        }

        if((paymentAccountArray != null) && (paymentAccountArray.toJSONArray().size() != (paymentAccountFractionArray.toJSONArray().size())))
            return new JO(); // contract not yet configured

        long returnFeeNQT = Convert.parseUnsignedLong(params.getString("returnFeeNQT"));
        long returnMinimumNQT = Convert.parseUnsignedLong(params.getString("returnMinimumNQT"));

        if(jsonTierArray.toJSONArray().size() <= 1 || (jsonTierArray.toJSONArray().size() != (jsonTierPromotionCostArray.toJSONArray().size() + 1)))
            return new JO(); // contract not yet configured

        String feePriorityString = params.getString("feePriority").toUpperCase();

        String contractNameString = context.getContractName();
        long contractAccount = Convert.parseUnsignedLong(context.getAccount());

        TransactionResponse triggerTransaction = context.getTransaction();

        long minFeeRateNQTPerFXT = Convert.parseUnsignedLong(params.getString("minRateNQTPerFXT"));
        long maxFeeRateNQTPerFXT = Convert.parseUnsignedLong(params.getString("maxRateNQTPerFXT"));

        JA rates = nxt.http.callers.GetBundlerRatesCall.create()
                .minBundlerBalanceFXT(10)
                .minBundlerFeeLimitFQT(1)
                .transactionPriority(feePriorityString)
                .call()
                .getArray("rates");

        for(JO rate : rates.objects()) {
            if(rate.getInt("chain") == chainId) {
                feeRateNQTPerFXT = Convert.parseUnsignedLong(rate.getString("minRateNQTPerFXT"));

                if(feeRateNQTPerFXT < minFeeRateNQTPerFXT)
                    feeRateNQTPerFXT = minFeeRateNQTPerFXT;

                if (feeRateNQTPerFXT > maxFeeRateNQTPerFXT)
                    feeRateNQTPerFXT = maxFeeRateNQTPerFXT;
            }
        }

        context.logInfoMessage("feeRateNQTPerFXT: " + feeRateNQTPerFXT);

        senderBalanceNQT = 0;
        totalCostNQT = 0;

        List<Long> listPaymentAccount = listAccountIdFromRSArray(paymentAccountArray);
        List<Double> listPaymentSplit = listDoubleFromJA(paymentAccountFractionArray);

        List<SortedSet<Long>> listSetTierDefinition = listSetFromJsonTierArray(jsonTierArray);
        List<Long> listTierPromotionCost = listLongFromJsonStringArray(jsonTierPromotionCostArray);

        if(listSetTierDefinition.size() == 0)
            return new JO();

        ApplicationTransactions applicationTransactions = new ApplicationTransactions();

        TreeMap<String, JO> transactionBalance = new TreeMap<>();
        HashMap<Integer, Long> countAssetReceivedPerTier = new HashMap<>();

        for(int i = 0; i < jsonTierArray.toJSONArray().size() - 1; i++) {
            countAssetReceivedPerTier.put(i, (long) 0);
        }

        TreeSet<String> transactionListReceived = new TreeSet<>();

        getReceivedTransactions(transactionListReceived, applicationTransactions, contractAccount, triggerTransaction.getSenderId(), chainId, contractNameString);

        /* NOTE If assets or payments are manually returned then these spent transaction's fullHash should be specified
           in the message attachment as JSON in string array "transactionSpent". */

        getSpentTransactionsFromSentAssetTransactionMessages(applicationTransactions, triggerTransaction.getSenderId(), contractAccount, chainId);

        filterTransactionListAndWithInvalidationCache(applicationTransactions, transactionListReceived);

        HashMap<Integer, HashMap<Long, Long>> tierAssetReceivedCountList = new HashMap<>();
        categorizeReceivedTransactions(applicationTransactions, listSetTierDefinition, transactionBalance, countAssetReceivedPerTier, chainId, tierAssetReceivedCountList);

        prepareRandom(context);

        HashMap<Long, Long> assetListPick = new HashMap<>();
        boolean validSetsAndBalance = verifyAllSetsCompletedAndCalculateTotalCostAndPickAssets(countAssetReceivedPerTier, listTierPromotionCost, assetCountForPromotion, listSetTierDefinition, assetListPick, tierAssetReceivedCountList, requireIdenticalPerPromotion);

        applicationTransactions.updateEcBlock(context);

        transactionContext.logInfoMessage("triggerFullHash: " + Convert.toHexString(triggerTransaction.getFullHash()) + " : " + triggerTransaction.getChainId());
        transactionContext.logInfoMessage("fork           : " + triggerTransaction.getHeight() + " : " + Long.toUnsignedString(triggerTransaction.getBlockId()));
        transactionContext.logInfoMessage("transaction EC : " + applicationTransactions.ecBlockHeight + " : " + Long.toUnsignedString(applicationTransactions.ecBlockId));

        if(!validSetsAndBalance) {
            context.logInfoMessage("balance : " + (senderBalanceNQT - totalCostNQT) + " = " + senderBalanceNQT + " - " + totalCostNQT);
            return new JO();
        }

        transactionMessageJOAppendContext(context, contractNameString, applicationTransactions);

        int timestampCacheExpiry = Nxt.getEpochTime() - 24 * 60 * 60 * 2;

        synchronized (invalidationCache) {
            invalidationCache.entrySet().removeIf(entry -> (entry.getValue() < timestampCacheExpiry ));

            for(String fullHash: applicationTransactions.transactionHashListFiltered) {
                invalidationCache.put(generateTransactionInvalidationHash(applicationTransactions, fullHash), Nxt.getEpochTime());
            }
        }

        broadcastPickedAssets(context, chainId, assetListPick, applicationTransactions);

        broadcastReturnExcessPayment(context, returnFeeNQT, returnMinimumNQT, chainId, applicationTransactions);

        broadcastPaymentSplit(context, listPaymentAccount, listPaymentSplit, chainId, applicationTransactions);

        return context.getResponse();
    }

    private void prepareRandom(TransactionContext context) {
        TransactionResponse triggerTransaction = context.getTransaction();

        JO params = context.getContractRunnerConfigParams(getClass().getSimpleName());

        try {
            random = SecureRandom.getInstance("SHA1PRNG");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e);
        }

        MessageDigest digest = Crypto.sha256();

        String secretForRandomString = params.getString("secretForRandomString");
        secretForRandomSerialString = params.getString("secretForRandomSerialString");

        byte[] secretForRandom;
        byte[] secretForRandomSerial;

        if(secretForRandomString != null) {
            secretForRandom = secretForRandomString.getBytes(StandardCharsets.UTF_8);
            digest.update(secretForRandom);
        }

        if(secretForRandomSerialString != null) {
            secretForRandomSerial = secretForRandomSerialString.getBytes(StandardCharsets.UTF_8);
            digest.update(secretForRandomSerial);
        }

        // random seed derived from long from HASH(secretForRandomSerialString | serial | getBlockId | getFullHash)
        digest.update(ByteBuffer.allocate(Long.BYTES).putLong(triggerTransaction.getBlockId()).array());
        digest.update(triggerTransaction.getFullHash());

        long derivedSeedForAssetPick = ByteBuffer.wrap(digest.digest(), 0, 8).getLong();
        random.setSeed(derivedSeedForAssetPick);

        transactionContext.logInfoMessage("random seed for invocation: " + derivedSeedForAssetPick);
    }

    private void broadcastPickedAssets(TransactionContext context, int chainId, HashMap<Long, Long> assetListPick, ApplicationTransactions applicationTransactions) {
        JO messageAttachment = transactionMessageJO;

        if(assetListPick.size() > 1) {
            messageAttachment = new JO();

            messageAttachment.put("submittedBy", context.getContractName());

            JO response = nxt.http.callers.SendMessageCall.create(chainId)
                    .privateKey(privateKey)
                    .recipient(context.getTransaction().getSenderId())
                    .message(transactionMessageJO.toJSONString()).messageIsText(true).messageIsPrunable(true)
                    .ecBlockHeight(applicationTransactions.ecBlockHeight)
                    .ecBlockId(applicationTransactions.ecBlockId)
                    .timestamp(applicationTransactions.timeStamp)
                    .deadline(transactionDeadline)
                    .feeRateNQTPerFXT(feeRateNQTPerFXT)
                    .broadcast(true)
                    .call();

            Logger.logInfoMessage(response.toJSONString());
        }

        for (long assetId : assetListPick.keySet()) {

            long quantityQNT = (long) (assetListPick.get(assetId) * Math.pow(10, getAssetDecimals(assetId)));

            JO response = nxt.http.callers.TransferAssetCall.create(chainId)
                    .privateKey(privateKey)
                    .recipient(context.getTransaction().getSenderId())
                    .message(messageAttachment.toJSONString()).messageIsText(true).messageIsPrunable(true)
                    .ecBlockHeight(applicationTransactions.ecBlockHeight)
                    .ecBlockId(applicationTransactions.ecBlockId)
                    .timestamp(applicationTransactions.timeStamp)
                    .deadline(transactionDeadline)
                    .feeRateNQTPerFXT(feeRateNQTPerFXT)
                    .asset(assetId)
                    .quantityQNT(quantityQNT)
                    .broadcast(true)
                    .call();

            Logger.logInfoMessage(response.toJSONString());
        }
    }

    private long randomPickAssetFromTieredList(List<SortedSet<Long>> tieredAssetDefinition, int tier) {
        long assetId = 0;
        double nextDouble = random.nextDouble();

        SortedSet<Long> assetList = tieredAssetDefinition.get(tier);

        int assetCount = assetList.size();
        int assetIndexPick = (int) (nextDouble * assetCount);

        transactionContext.logInfoMessage("random for pick : " + nextDouble + " : randomIndex : " + assetIndexPick + " / " + (assetCount - 1));

        int index = 0;

        for (long assetIdPick: assetList) {

            if(index++ < assetIndexPick)
                continue;

            assetId = assetIdPick;
            break;
        }

        return assetId;
    }

    private void broadcastPaymentSplit(TransactionContext context, List<Long> listAccounts, List<Double> listFraction, int chainId, ApplicationTransactions applicationTransactions) {

        if(listAccounts == null || listFraction == null)
            return;

        int count = listAccounts.size();

        for(int i = 0; i < count; i++) {
            long recipient = listAccounts.get(i);
            double fraction = listFraction.get(i);

            if (recipient == Convert.parseAccountId(context.getAccount()))
                continue;

            long amountNQT = (long) ((double)totalCostNQT * fraction); // NOTE sender needs extra balance to support variable fee

            if (amountNQT <= 0)
                continue;

            JO response = nxt.http.callers.SendMoneyCall.create(chainId)
                    .privateKey(privateKey)
                    .recipient(recipient)
                    .message(transactionMessageJO.toJSONString()).messageIsText(true).messageIsPrunable(true)
                    .ecBlockHeight(applicationTransactions.ecBlockHeight)
                    .ecBlockId(applicationTransactions.ecBlockId)
                    .timestamp(applicationTransactions.timeStamp)
                    .deadline(transactionDeadline)
                    .feeRateNQTPerFXT(feeRateNQTPerFXT)
                    .amountNQT(amountNQT)
                    .broadcast(true)
                    .call();

            Logger.logInfoMessage(response.toJSONString());
        }
    }

    private void broadcastReturnExcessPayment(TransactionContext context, long returnFeeNQT, long returnMinimumNQT, int chainId, ApplicationTransactions applicationTransactions) {
        long recipient = context.getTransaction().getSenderId();

        long amountNQT = senderBalanceNQT - (totalCostNQT + returnFeeNQT);

        if(amountNQT < returnMinimumNQT)
            return;

        JO response = nxt.http.callers.SendMoneyCall.create(chainId)
                .privateKey(privateKey)
                .recipient(recipient)
                .message(transactionMessageJO.toJSONString()).messageIsText(true).messageIsPrunable(true)
                .ecBlockHeight(applicationTransactions.ecBlockHeight)
                .ecBlockId(applicationTransactions.ecBlockId)
                .timestamp(applicationTransactions.timeStamp)
                .deadline(transactionDeadline)
                .feeNQT(returnFeeNQT)
                .amountNQT(amountNQT)
                .broadcast(true)
                .call();

        Logger.logInfoMessage(response.toJSONString());
    }

    private boolean verifyAllSetsCompletedAndCalculateTotalCostAndPickAssets(HashMap<Integer, Long> countAssetReceivedPerTier, List<Long> tierPromotionCost, long requiredAssetsPerTier, List<SortedSet<Long>> tieredAssetDefinition, HashMap<Long, Long> assetListPick, HashMap<Integer, HashMap<Long, Long>> tierAssetReceivedCountList, boolean requireIdenticalPerPromotion) {
        boolean isValid = true;

        long totalPickCount = 0;

        for (int tier = 0; tier < countAssetReceivedPerTier.size(); tier++) {
            long tierAssetCount = countAssetReceivedPerTier.get(tier);

            if(tierAssetCount % requiredAssetsPerTier != 0) {
                transactionContext.logInfoMessage("quit : missing " + (requiredAssetsPerTier - (tierAssetCount % requiredAssetsPerTier)) + " to complete set for tier");
                isValid = false;
                break;
            }

            // this could be adapted to a per-tier rule.
            if(requireIdenticalPerPromotion && tierAssetReceivedCountList.containsKey(tier)) {

                HashMap<Long, Long> assetReceivedCountList = tierAssetReceivedCountList.get(tier);

                for (long assetId : assetReceivedCountList.keySet()) {
                    if (assetReceivedCountList.get(assetId) % requiredAssetsPerTier != 0) {
                        transactionContext.logInfoMessage("quit : requireIdenticalPerPromotion : asset " + Long.toUnsignedString(assetId) + " : " + assetReceivedCountList.get(assetId));
                        return false;
                    }
                }
            }

            long pickCount = tierAssetCount / requiredAssetsPerTier;

            for(long j = 0; j < pickCount; j++) {
                long assetId = randomPickAssetFromTieredList(tieredAssetDefinition, tier + 1);

                long assetCount = 1;

                if(assetListPick.containsKey(assetId)) {
                    assetCount += assetListPick.get(assetId);
                }

                assetListPick.put(assetId, assetCount);
            }

            if(pickCount > 0) {
                transactionContext.logInfoMessage("tier : " + tier + " ; promotion count : " + pickCount + " ; total tier promotion cost : " + (tierPromotionCost.get(tier) * pickCount));
            }

            totalCostNQT += tierPromotionCost.get(tier) * pickCount;

            totalPickCount += pickCount;

            if(senderBalanceNQT >= totalCostNQT)
                continue;

            isValid = false;
            break;
        }

        if(totalPickCount == 0)
            isValid = false;

        return isValid;
    }

    private void transactionMessageJOAppendContext(TransactionContext context, String contractNameString, ApplicationTransactions applicationTransactions) {
        transactionMessageJO.put("submittedBy", contractNameString);
        transactionMessageJO.put("transactionTrigger", Convert.toHexString(context.getTransaction().getFullHash()));

        if(secretForRandomSerialString != null) {
            transactionMessageJO.put("serialForRandom", secretForRandomSerialString);
        }

        JSONArray transactionListSpentJA = new JSONArray();

        transactionMessageJO.put("transactionSpent", transactionListSpentJA);

        transactionListSpentJA.addAll(applicationTransactions.transactionHashListFiltered);

        transactionMessageJO.put("amountNQTReceived", senderBalanceNQT);
        transactionMessageJO.put("amountNQTSpent", totalCostNQT);
    }

    private void categorizeReceivedTransactions(ApplicationTransactions applicationTransactions, List<SortedSet<Long>> tieredAssetDefinition, TreeMap<String, JO> transactionBalance, HashMap<Integer, Long> countAssetReceivedPerTier, int chainIdForPayment, HashMap<Integer, HashMap<Long, Long>> tierAssetReceivedCountList){

        for (String fullHash: applicationTransactions.transactionHashListFiltered) {
            JO transactionJO = applicationTransactions.transactionCache.get(fullHash);

            int type = transactionJO.getInt("type");
            int subtype = transactionJO.getInt("subtype");

            switch(type) {

                case 2: {
                    if(subtype != 1)
                        continue;

                    JO attachment = transactionJO.getJo("attachment");

                    if(attachment == null) //
                        continue;

                    String assetIdString = attachment.getString("asset");
                    long assetId = Long.parseUnsignedLong(assetIdString);

                    int assetTier = getAssetTier(tieredAssetDefinition, assetId);

                    if(assetTier < 0) {

                        /* NOTE these transactions will be spent with the next valid trigger so that they can be safely refunded manually,
                        otherwise mention spend with the refund message attachment. */

                        transactionContext.logInfoMessage(fullHash + " : received invalid asset : " + assetIdString);
                        continue;
                    }

                    long assetCount = (long) (Long.parseUnsignedLong(attachment.getString("quantityQNT")) / Math.pow(10, getAssetDecimals(assetId)));

                    transactionContext.logInfoMessage(fullHash + " : received asset : " + assetIdString + "  (+" + assetCount + ")   tier : " + assetTier);

                    long assetCountTotalPerTier = assetCount;

                    if(countAssetReceivedPerTier.containsKey(assetTier)) {
                        assetCountTotalPerTier += countAssetReceivedPerTier.get(assetTier);
                    }

                    countAssetReceivedPerTier.put(assetTier, assetCountTotalPerTier);

                    {
                        if (!tierAssetReceivedCountList.containsKey(assetTier)) {
                            tierAssetReceivedCountList.put(assetTier, new HashMap<>());
                        }

                        HashMap<Long, Long> assetReceivedCountList = tierAssetReceivedCountList.get(assetTier);

                        if (assetReceivedCountList.containsKey(assetId)) {
                            assetCount += assetReceivedCountList.get(assetId);
                        }

                        assetReceivedCountList.put(assetId, assetCount);
                    }

                    applicationTransactions.putPaymentTransaction(transactionJO);

                    break; //
                }

                case 0: {
                    if(subtype != 0)
                        continue;

                    int chainId = transactionJO.getInt("chain");

                    if(chainId != chainIdForPayment) // already filtered with getReceivedTransactions
                        continue;

                    senderBalanceNQT += Long.parseUnsignedLong(transactionJO.getString("amountNQT"));
                    transactionBalance.put(fullHash, transactionJO);

                    transactionContext.logInfoMessage(fullHash + " : received amountNQT : " + transactionJO.getLong("amountNQT"));

                    applicationTransactions.putPaymentTransaction(transactionJO);

                    break;
                }

                default:
            }
        }
    }

    private String generateTransactionInvalidationHash(ApplicationTransactions applicationTransactions, String fullHash) {
        JO transactionJO = applicationTransactions.transactionCache.get(fullHash);
        return transactionJO.getString("block") + fullHash;
    }

    private int getAssetDecimals(long assetId) {
        int assetDecimal = 0;

        boolean cached = false;

        synchronized (assetDecimalCache) {
            if(assetDecimalCache.containsKey(assetId)) {
                cached = true;
                assetDecimal = assetDecimalCache.get(assetId);
            }
        }

        if(!cached) {
            assetDecimal = nxt.http.callers.GetAssetCall.create().asset(assetId).call().getInt("decimals");

            synchronized (assetDecimalCache) {
                assetDecimalCache.put(assetId, assetDecimal);
            }
        }

        return assetDecimal;
    }

    private int getAssetTier(List<SortedSet<Long>> tieredAssetDefinition, long assetId) {
        int tier = -1;
        int tieredAssetDefinitionSize = tieredAssetDefinition.size();

        for (int i = 0; i < tieredAssetDefinitionSize - 1; i++) {

            SortedSet<Long> assetList = tieredAssetDefinition.get(i);

            if(!assetList.contains(assetId))
                continue;

            tier = i;
            break;
        }

        return  tier;
    }

    private List<String> listStringFromJA(JA jsonArray) {

        int jsonArraySize = jsonArray.toJSONArray().size();

        if( jsonArraySize == 0)
            return null;

        List<String> list = new ArrayList<>();

        for(int i = 0; i < jsonArraySize; i++) {
            list.add((jsonArray.toJSONArray().get(i).toString()));
        }

        return list;
    }

    private List<Double> listDoubleFromJA(JA jsonValueArray) {

        int jsonArraySize = jsonValueArray.toJSONArray().size();

        if( jsonArraySize == 0)
            return null;

        List<Double> list = new ArrayList<>();

        for(int i = 0; i < jsonArraySize; i++) {
            list.add(Double.parseDouble((jsonValueArray.toJSONArray().get(i).toString())));
        }

        return list;
    }

    private List<Long> listAccountIdFromRSArray(JA jsonStringArray) {

        int jsonArraySize = jsonStringArray.toJSONArray().size();

        if( jsonArraySize == 0)
            return null;

        List<Long> list = new ArrayList<>();

        for(int i = 0; i < jsonArraySize; i++) {
            list.add(Convert.parseAccountId((jsonStringArray.toJSONArray().get(i).toString())));
        }

        return list;
    }

    private List<Long> listLongFromJsonStringArray(JA jsonStringArray) {

        int jsonArraySize = jsonStringArray.toJSONArray().size();

        if( jsonArraySize == 0)
            return null;

        List<Long> list = new ArrayList<>();

        for(int i = 0; i < jsonArraySize; i++) {
            list.add(Long.parseUnsignedLong(jsonStringArray.toJSONArray().get(i).toString()));
        }

        return list;
    }

    private List<SortedSet<Long>> listSetFromJsonTierArray(JA jsonTierArray) {

        int jsonTierArraySize = jsonTierArray.size();

        if( jsonTierArraySize == 0)
            return null;

        List<SortedSet<Long>> list = new ArrayList<>();

        for(int i = 0; i < jsonTierArraySize; i++) {
            list.add(new TreeSet<>());

            JA tierSetJA = jsonTierArray.getArray(i);
            int tierSetJASize = tierSetJA.toJSONArray().size();

            for(int j = 0; j < tierSetJASize; j++) {
                list.get(i).add(Long.parseUnsignedLong(tierSetJA.toJSONArray().get(j).toString()));
            }
        }

        return list;
    }

    private void filterTransactionListAndWithInvalidationCache(ApplicationTransactions applicationTransactions, TreeSet<String> transactionListReceived) {

        for (String fullHash: transactionListReceived) {

            if(applicationTransactions.transactionHashListSpent.contains(fullHash))
                continue;

            synchronized (invalidationCache) {
                if (invalidationCache.containsKey(generateTransactionInvalidationHash(applicationTransactions, fullHash))) {
                    continue;
                }
            }

            applicationTransactions.transactionHashListFiltered.add(fullHash);
        }
    }

    private void getReceivedTransactions(TreeSet<String> transactionList, ApplicationTransactions applicationTransactions, long recipient, long sender, int chainId, String contractNameString) {

        int triggerTransactionHeight = transactionContext.getTransaction().getHeight();

        JO response = nxt.http.callers.GetExecutedTransactionsCall.create(chainId)
                .adminPassword(adminPasswordString)
                .recipient(recipient)
                .sender(sender)
                .call();

        JA arrayOfTransactions = response.getArray("transactions");

        for (Object transactionObject : arrayOfTransactions) {
            JO transactionJO = (JO)transactionObject;

            int type = transactionJO.getInt("type");
            int subtype = transactionJO.getInt("subtype");

            if (!((type == 0 && subtype == 0) || (type == 2 && subtype == 1)))
                continue;

            JO attachment = transactionJO.getJo("attachment");

            if (attachment == null)
                continue;

            if (!attachment.isExist("version.PrunablePlainMessage"))
                continue;

            if(!attachment.isExist("messageIsText")) {
                continue;
            }

            if (!attachment.getBoolean("messageIsText"))
                continue;

            String message = attachment.getString("message");

            if (message == null)
                continue;

            JO messageAsJson = null;

            try {
                messageAsJson = JO.parse(message);
            } catch (IllegalArgumentException e) {/* empty */}

            if (messageAsJson == null)
                continue;

            if(messageAsJson.isExist("contract")) {
                if (!messageAsJson.getString("contract").equals(contractNameString))
                    continue;
            } else {
                continue;
            }

            int blockHeight = transactionJO.getInt("height");

            if(blockHeight > triggerTransactionHeight) {
                break;
            }

            String fullHashString = transactionJO.getString("fullHash");
            transactionList.add(fullHashString);
            applicationTransactions.transactionCache.put(fullHashString, transactionJO);
        }
    }

    private void getSpentTransactionsFromSentAssetTransactionMessages(ApplicationTransactions applicationTransactions, long recipient, long sender, int chainId) {

        JO response = nxt.http.callers.GetExecutedTransactionsCall.create(chainId).recipient(recipient).sender(sender).adminPassword(adminPasswordString).call();
        JA arrayOfTransactions = response.getArray("transactions");

        for (Object object : arrayOfTransactions) {
            JO jo = (JO)object;
            JO attachment = jo.getJo("attachment");

            if (attachment == null)
                continue;

            if (!attachment.getBoolean("messageIsText"))
                continue;

            String message = attachment.getString("message");

            if (message == null)
                continue;

            JO messageAsJson = null;

            try {
                messageAsJson = JO.parse(message);
            } catch (IllegalArgumentException e) {/* empty */}

            if (messageAsJson == null)
                continue;

            JA invalidatedTransactionArray = messageAsJson.getArray("transactionSpent");

            if (invalidatedTransactionArray == null)
                continue;

            int countOfSpentTransactions = invalidatedTransactionArray.size();
            List<String> listFullHashSpent = listStringFromJA(invalidatedTransactionArray);

            for (int j = 0; j < countOfSpentTransactions; j++) {
                applicationTransactions.transactionHashListSpent.add(listFullHashSpent.get(j));
            }
        }
    }
}
