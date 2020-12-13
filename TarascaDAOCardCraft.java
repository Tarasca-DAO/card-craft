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

    SecureRandom random;

    private long feeRateNQTPerFXT = 0;

    JO transactionMessageJO = new JO();

    private long senderBalanceNQT = 0;
    private long totalCostNQT = 0;

    String secretForRandomSerialString;
    byte[] privateKey;

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

            privateKey = hexStringToByteArray(privateKeyHexString);
        }

        JA jsonTierArray = params.getArray("tieredAssetIds");
        JA jsonTierPromotionCostArray = params.getArray("tierPromotionCost");
        long assetCountForPromotion = Convert.parseUnsignedLong(params.getString("tierPromotionRequiredCount"));

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

        TreeMap<String, JO> transactionBalance = new TreeMap<>();
        HashMap<Integer, Long> countAssetReceivedPerTier = new HashMap<>();

        for(int i = 0; i < jsonTierArray.toJSONArray().size() - 1; i++) {
            countAssetReceivedPerTier.put(i, (long) 0);
        }

        TreeSet<String> transactionListFiltered = new TreeSet<>();
        TreeSet<String> transactionListReceived = new TreeSet<>();
        TreeSet<String> transactionListSpent = new TreeSet<>();
        TreeMap<String, JO> transactionCache = new TreeMap<>();

        getReceivedTransactions(transactionListReceived, transactionCache, contractAccount, triggerTransaction.getSenderId(), chainId, contractNameString);

        /* NOTE If assets or payments are manually returned then these spent transaction's fullHash should be specified
           in the message attachment as JSON in string array "transactionSpent". */

        getSpentTransactionsFromSentAssetTransactionMessages(transactionListSpent, triggerTransaction.getSenderId(), contractAccount, chainId);

        filterTransactionListAndWithInvalidationCache(transactionListFiltered, transactionListReceived, transactionListSpent);

        categorizeReceivedTransactions(transactionListFiltered, listSetTierDefinition, transactionCache, transactionBalance, countAssetReceivedPerTier, chainId);

        prepareRandom(context);

        HashMap<Long, Long> assetListPick = new HashMap<>();
        boolean validSetsAndBalance = verifyAllSetsCompletedAndCalculateTotalCostAndPickAssets(countAssetReceivedPerTier, listTierPromotionCost, assetCountForPromotion, listSetTierDefinition, assetListPick);

        if(!validSetsAndBalance) {
            context.logInfoMessage("balance : " + (senderBalanceNQT - totalCostNQT) + " = " + senderBalanceNQT + " - " + totalCostNQT);
            return new JO();
        }

        transactionMessageJOAppendContext(context, contractNameString, transactionListFiltered);

        int timestampCacheExpiry = Nxt.getEpochTime() - 24 * 60 * 60 * 2;

        synchronized (invalidationCache) {
            invalidationCache.entrySet().removeIf(entry -> (entry.getValue() < timestampCacheExpiry ));

            for(String fullHash: transactionListFiltered) {
                invalidationCache.put(fullHash, Nxt.getEpochTime());
            }
        }

        broadcastPickedAssets(context, chainId, assetListPick);

        broadcastReturnExcessPayment(context, returnFeeNQT, returnMinimumNQT, chainId);

        broadcastPaymentSplit(context, listPaymentAccount, listPaymentSplit, chainId);

        return context.getResponse();
    }

    private void prepareRandom(TransactionContext context) {
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
        digest.update(ByteBuffer.allocate(Long.BYTES).putLong(context.getBlock().getBlockId()).array());
        digest.update(context.getTransaction().getFullHash());

        long derivedSeedForAssetPick = ByteBuffer.wrap(digest.digest(), 0, 8).getLong();
        random.setSeed(derivedSeedForAssetPick);
    }

    private void broadcastPickedAssets(TransactionContext context, int chainId, HashMap<Long, Long> assetListPick) {
        JO messageAttachment = transactionMessageJO;

        if(assetListPick.size() > 1) {
            messageAttachment = new JO();

            messageAttachment.put("submittedBy", context.getContractName());

            JO response = nxt.http.callers.SendMessageCall.create(chainId)
                    .privateKey(privateKey)
                    .recipient(context.getTransaction().getSenderId())
                    .message(transactionMessageJO.toJSONString()).messageIsText(true).messageIsPrunable(true)
                    .ecBlockHeight(context.getBlock().getHeight())
                    .ecBlockId(context.getBlock().getBlockId())
                    .timestamp(context.getBlock().getTimestamp())
                    .deadline(1440)
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
                    .ecBlockHeight(context.getBlock().getHeight())
                    .ecBlockId(context.getBlock().getBlockId())
                    .timestamp(context.getBlock().getTimestamp())
                    .deadline(1440)
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

        int index = 0;

        for (long assetIdPick: assetList) {

            if(index++ < assetIndexPick)
                continue;

            assetId = assetIdPick;
            break;
        }

        return assetId;
    }

    private void broadcastPaymentSplit(TransactionContext context, List<Long> listAccounts, List<Double> listFraction, int chainId) {

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
                    .ecBlockHeight(context.getBlock().getHeight())
                    .ecBlockId(context.getBlock().getBlockId())
                    .timestamp(context.getBlock().getTimestamp())
                    .deadline(1440)
                    .feeRateNQTPerFXT(feeRateNQTPerFXT)
                    .amountNQT(amountNQT)
                    .broadcast(true)
                    .call();

            Logger.logInfoMessage(response.toJSONString());
        }
    }

    private void broadcastReturnExcessPayment(TransactionContext context, long returnFeeNQT, long returnMinimumNQT, int chainId) {
        long recipient = context.getTransaction().getSenderId();

        long amountNQT = senderBalanceNQT - (totalCostNQT + returnFeeNQT);

        if(amountNQT < returnMinimumNQT)
            return;

        JO response = nxt.http.callers.SendMoneyCall.create(chainId)
                .privateKey(privateKey)
                .recipient(recipient)
                .message(transactionMessageJO.toJSONString()).messageIsText(true).messageIsPrunable(true)
                .ecBlockHeight(context.getBlock().getHeight())
                .ecBlockId(context.getBlock().getBlockId())
                .timestamp(context.getBlock().getTimestamp())
                .deadline(1440)
                .feeNQT(returnFeeNQT)
                .amountNQT(amountNQT)
                .broadcast(true)
                .call();

        Logger.logInfoMessage(response.toJSONString());
    }

    private boolean verifyAllSetsCompletedAndCalculateTotalCostAndPickAssets(HashMap<Integer, Long> countAssetReceivedPerTier, List<Long> tierPromotionCost, long requiredAssetsPerTier, List<SortedSet<Long>> tieredAssetDefinition, HashMap<Long, Long> assetListPick) {
        boolean isValid = true;

        long totalPickCount = 0;

        for (int tier = 0; tier < countAssetReceivedPerTier.size(); tier++) {
            long tierAssetCount = countAssetReceivedPerTier.get(tier);

            if(tierAssetCount % requiredAssetsPerTier != 0) {
                transactionContext.logInfoMessage("quitting : missing " + (requiredAssetsPerTier - (tierAssetCount % requiredAssetsPerTier)) + " to complete set for tier");
                isValid = false;
                break;
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

    private void transactionMessageJOAppendContext(TransactionContext context, String contractNameString, TreeSet<String> transactionList) {
        transactionMessageJO.put("submittedBy", contractNameString);
        transactionMessageJO.put("transactionTrigger", Convert.toHexString(context.getTransaction().getFullHash()));

        if(secretForRandomSerialString != null) {
            transactionMessageJO.put("serialForRandom", secretForRandomSerialString);
        }

        JSONArray transactionListSpentJA = new JSONArray();

        transactionMessageJO.put("transactionSpent", transactionListSpentJA);

        transactionListSpentJA.addAll(transactionList);

        transactionMessageJO.put("amountNQTRecevied", senderBalanceNQT);
        transactionMessageJO.put("amountNQTSpent", totalCostNQT);
    }

    private void categorizeReceivedTransactions(TreeSet<String> transactionList, List<SortedSet<Long>> tieredAssetDefinition, TreeMap<String, JO> transactionCache, TreeMap<String, JO> transactionBalance, HashMap<Integer, Long> countAssetReceivedPerTier, int chainIdForPayment){

        for (String fullHash: transactionList) {
            JO transactionJO = transactionCache.get(fullHash);

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

                    assetCount += countAssetReceivedPerTier.get(assetTier);
                    countAssetReceivedPerTier.put(assetTier, assetCount);
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

                    break;
                }

                default:
            }
        }
    }

    private int getAssetDecimals(long assetId) {

        return nxt.http.callers.GetAssetCall.create().asset(assetId).call().getInt("decimals");
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

    private void filterTransactionListAndWithInvalidationCache(TreeSet<String> transactionListFiltered, TreeSet<String> transactionListReceived, TreeSet<String> transactionListSpent) {

        for (String fullHash: transactionListReceived) {

            if(transactionListSpent.contains(fullHash))
                continue;

            synchronized (invalidationCache) {
                if (invalidationCache.containsKey(fullHash)) {
                    continue;
                }
            }

            transactionListFiltered.add(fullHash);
        }
    }

    private void getReceivedTransactions(TreeSet<String> transactionList, TreeMap<String, JO> transactionCache, long recipient, long sender, int chainId, String contractNameString) {

        JO response = nxt.http.callers.GetExecutedTransactionsCall.create(chainId)
                .recipient(recipient)
                .sender(sender)
                .call();

        JA arrayOfTransactions = response.getArray("transactions");

        int countOfSentTransactions = arrayOfTransactions.size();

        for(int i = 0; i < countOfSentTransactions; i++) {
            JO transactionJO = arrayOfTransactions.get(i);

            int type = transactionJO.getInt("type");
            int subtype = transactionJO.getInt("subtype");

            if(! ((type == 0 && subtype == 0)  || (type == 2 && subtype == 1)))
                continue;

            JO attachment = transactionJO.getJo("attachment");

            if(attachment == null)
                continue;

            if(!attachment.getBoolean("messageIsText"))
                continue;

            String message = attachment.getString("message");

            if(message == null)
                continue;
            JO messageAsJson = null;

            try { messageAsJson = JO.parse(message); } catch(IllegalArgumentException e) {/* empty */}

            if(messageAsJson == null)
                continue;

            if(!messageAsJson.getString("contract").equals(contractNameString))
                continue;

            String fullHashString = transactionJO.getString("fullHash");
            transactionList.add(fullHashString);
            transactionCache.put(fullHashString, transactionJO);
        }
    }

    private void getSpentTransactionsFromSentAssetTransactionMessages(TreeSet<String> transactionList, long recipient, long sender, int chainId) {

        JO response = nxt.http.callers.GetExecutedTransactionsCall.create(chainId).recipient(recipient).sender(sender).call();
        JA arrayOfTransactions = response.getArray("transactions");

        int countOfSentAssetTransactions = arrayOfTransactions.size();

        for(int i = 0; i < countOfSentAssetTransactions; i++) {
            JO jo = arrayOfTransactions.get(i);

            JO attachment = jo.getJo("attachment");

            if(attachment == null)
                continue;

            if(!attachment.getBoolean("messageIsText"))
                continue;

            String message = attachment.getString("message");

            if(message == null)
                continue;

            JO messageAsJson = null;

            try { messageAsJson = JO.parse(message); } catch(IllegalArgumentException e) {/* empty */}

            if(messageAsJson == null)
                continue;

            JA invalidatedTransactionArray = messageAsJson.getArray("transactionSpent");

            if(invalidatedTransactionArray == null)
                continue;

            int countOfSpentTransactions = invalidatedTransactionArray.size();
            List<String> listSpentFullHash = listStringFromJA(invalidatedTransactionArray);

            for(int j = 0; j < countOfSpentTransactions; j++) {
                transactionList.add(listSpentFullHash.get(j));
            }
        }
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];

        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }

        return data;
    }
}
