// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "key_io.h"
#include "main.h"
#include "crypto/equihash.h"

#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

#include "chainparamsseeds.h"

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, const uint256& nNonce, const std::vector<unsigned char>& nSolution, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    // To create a genesis block for a new chain which is Overwintered:
    //   txNew.nVersion = OVERWINTER_TX_VERSION
    //   txNew.fOverwintered = true
    //   txNew.nVersionGroupId = OVERWINTER_VERSION_GROUP_ID
    //   txNew.nExpiryHeight = <default value>
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 520617983 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nSolution = nSolution;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(txNew);
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = genesis.BuildMerkleTree();
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database (and is in any case of zero value).
 *
 * >>> from pyblake2 import blake2s
 * >>> blake2s(b'The Economist 2018-01-12 Known unknown: Another crypto-currency is born. BTC#503839 0000000000000000004d36fd42f981a9ac1330715488a274b29503e1f7ed5337 ETH#4895317 x54096447e0a988064db2e6dc19a17f216d9bd66bbf697ad5716899d1cf2be780 DJIA close on 10 Jan 2018: 15,134.68').hexdigest()
 *
 * CBlock(hash=00040fe8, ver=4, hashPrevBlock=00000000000000, hashMerkleRoot=c4eaa5, nTime=1477641360, nBits=1f07ffff, nNonce=4695, vtx=1)
 *   CTransaction(hash=c4eaa5, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff071f0104455a6361736830623963346565663862376363343137656535303031653335303039383462366665613335363833613763616331343161303433633432303634383335643334)
 *     CTxOut(nValue=0.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: c4eaa5
 */
static CBlock CreateGenesisBlock(uint32_t nTime, const uint256& nNonce, const std::vector<unsigned char>& nSolution, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "cdb44b93f35e78c9a750a523615ef22a72c499805de2b20833cd2eaaa0977027";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nSolution, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

const arith_uint256 maxUint = UintToArith256(uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        strCurrencyUnits = "ASF";
        bip44CoinType = 296; // As registered in https://github.com/satoshilabs/slips/blob/master/slip-0044.md
        consensus.fCoinbaseMustBeProtected = true;
        consensus.nSubsidySlowStartInterval = 0;
        consensus.nPreBlossomSubsidyHalvingInterval = Consensus::PRE_BLOSSOM_HALVING_INTERVAL;
        consensus.nPostBlossomSubsidyHalvingInterval = Consensus::POST_BLOSSOM_HALVING_INTERVAL;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 4000;
        const size_t N = 144, K = 5;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        consensus.nEquihashN = N;
        consensus.nEquihashK = K;

        eh_epoch_1 = eh200_9;
        eh_epoch_2 = eh144_5;
        eh_epoch_1_endblock = 90000;
        eh_epoch_2_startblock = 89500;

        consensus.powLimit = uint256S("0007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 32; // 32% adjustment down
        consensus.nPowMaxAdjustUp = 16; // 16% adjustment up
        consensus.nPreBlossomPowTargetSpacing = Consensus::PRE_BLOSSOM_POW_TARGET_SPACING;
        consensus.nPostBlossomPowTargetSpacing = Consensus::POST_BLOSSOM_POW_TARGET_SPACING;
        consensus.nPowAllowMinDifficultyBlocksAfterHeight = boost::none;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nActivationHeight =
            Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nProtocolVersion = 170018;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nActivationHeight = 310600;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nProtocolVersion = 170020;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight = 310610;
        consensus.vUpgrades[Consensus::UPGRADE_BLOSSOM].nProtocolVersion = 170022;
        consensus.vUpgrades[Consensus::UPGRADE_BLOSSOM].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("000000000000000000000000000000000000000000000000017e73a331fae01c");

        /**
         * The message start string should be awesome! ⓩ❤
         */
        pchMessageStart[0] = 0x24;
        pchMessageStart[1] = 0xe9;
        pchMessageStart[2] = 0x27;
        pchMessageStart[3] = 0x64;
        vAlertPubKey = ParseHex("047981778f47130d6ea06f36cd765c53d0f8d7a3b1dcf7388718666fc743e010d060289919a622371899333b821aaf8e480bda65a8f8dfffb39a875eb9b114805d");
        nDefaultPort = 8585;
        nPruneAfterHeight = 100000;

        genesis = CreateGenesisBlock(
            1515781463,
            uint256S("0x000000000000000000000000000000000000000000000000000000000000058f"),
            ParseHex("00a11b436d0d79706fcd079af85fe65e97443b03a5091fad4fa4848d22cdf7712399a71b70520b8838f807026939f417fdc2eb9cd166d54dddf7202afccb3c3b2a3797dceeec8d79c7a58c3c7d32adcd0553781f0a9a44b49f236c9f71fc68ed0fdc764e60dbfae52c2e509e029f985c6d353f83c702c24bf1c36a9080c938905c83c9b5dd63b758e46eedc4b7852b525338503ddeae47c7550a91a423869fe2cdd741e5da33781d027491d3fcd426d57ecd40f2d5dd280317a2fe76750543126e6a4f6893f47200a038f7b0553777953ed6063b67757772f661f4a0d776eee7387e2f8e3971541068efbdb0d5c3a0c6d2011c43b9f1e968f39579a00860510ad1cf485744fd2104578884bcdbf57302ac152bd6b9c6a8287f5279f3070c21fcc6c7b85cb67f1d2bcbbfee09065a8ab1196bb77669c69f64be42c61ea97e68fef01bcd84fa82e2ba9e135ecc8c57674900d8f43ba28df0cfda82902c384e31f01eb150f43c175287becbda3afceb90c5bbee6ca831fe009ff87512c5d36f62d1ae41236a927c55709c269070ba64482ea07b7eadcf31a39869744cd6744a9d2074d6202003151fef180ba975251f630384cd2cad77f41cbe6b0d69eabd4e774351ba484146af20315dbb9f6e9efc112c06f459876d3accb434e687ff748a110ef22c7e2392aa487dd8cfa8cf5af449194c41a6142d74912b04422e6aee0d5d95293821c068b2a78b74e51e067d11258c43db73fd7de78325592dcfb1699958ae9dcf0cea9a09960afe737999410504635d924946d517e30da0a61fc114d65cae70b4bfc94567d1c3bfd360710536f56efcd56d2cf98a66c85ccd4fb21dee58228707093c9d692b39dbf7ff622adda35639a619f84ce20d34afc83319db672a5040ef2534de055d3e5a9c8724a2f96c31b89d3be1c55270e3c900b142c5bcd20a013486da07886bd1682c831d7addd85cfa3528bc7a0b3f9c37e00673aa92e181e6891b1aa48138261e66100b63d42a2a2ae3e95151e935e08b551daa57dd3e1fd205b562b0d265e32ed47482ce2919f47993556a08665b0d25ccf45b228740d1e12fe3604bb5a429981d16d4c71b6611a7345365124661999361911e26c9229b829aab1baf6d3eb9a4870ede2855d56b7d91c03c97b7acf2d2ac7f0696e4411af52322f254def49401707c89022e4015ec5d70390c7e5998e8e75d8d08249a4e3e820e8d715101c631b4f6ee3e9e7bdaa6ee044f03e42193f97afce610ee72bba8e1f0195ff0331ee4c377692e6de1d9d8d2c67a614f19ce041e61560a30bbbc08d294fbb2c510ad13d773a2f8dd7d55110bee890c544c5f15fcecb2285ce4604612f9bd602e10ed73bad3dc7c6dca31e18bb3d7c82d19986a033728b051ddf0d8e533451156b6014c1445b967beaf4c030e5e7a4c9df5096caf634e30edc535c1f4beabb5042d9e0e7ddc3eb1f13b112ad029d06e431d1fb5f310e4a54bf8f01ae982c51147598be3da2f067454a727641f1bb7a523d53185352512300e1ddcad8f068d0fb24fd658b2a06bce1e62529a4a43e542cd78f0be169f374dbe903239d0c921946dc555416ff7d03d9616469d33ab8769cfecd371f0f29832e53372ca4e0c339c65d22e536cd3e5e3845d7da9a6de4d25dee6f5053f7fb9c79103cfe1e35426bd5e52b950af9245a73275d4fc9f4e09f9150dc450da333d8977806e50382fd8dec0476f2f5b8176f5e125e1921d9336b1fc3c66e45c3d1b6223394821c84e94e0878f80ab7f9f820b864308fd51b328bb65282ea6ccda1ad285188d220be574421fcf44f6b3de8101efe7fc21aa81decfd50b8dbf6ff29c30aefa73d1fc5725b6b5a511b9bd0c10de7c491b225f5b68f3f3b60a2cb6b91ce4cdb163"),
            0x1f07ffff, 4, 0);

        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0000363adb70e2cee5171918dc4ced36fa712abbb057b4807fff56d598b74be4"));
        assert(genesis.hashMerkleRoot == uint256S("0xdf6fc210ea76d364af851fd7ce5479f717cb8f4a1a4e577f15722933b532875b"));

        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.push_back(CDNSSeedData("asofe.org", "dnsseed.asofe.org")); // AsofeSeed

        // guarantees the first 2 characters, when base58 encoded, are "t1"
        base58Prefixes[PUBKEY_ADDRESS]     = {0x1C,0xB8};
        // guarantees the first 2 characters, when base58 encoded, are "t3"
        base58Prefixes[SCRIPT_ADDRESS]     = {0x1C,0xBD};
        // the first character, when base58 encoded, is "5" or "K" or "L" (as in Bitcoin)
        base58Prefixes[SECRET_KEY]         = {0x80};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04,0x88,0xB2,0x1E};
        base58Prefixes[EXT_SECRET_KEY]     = {0x04,0x88,0xAD,0xE4};
        // guarantees the first 2 characters, when base58 encoded, are "zc"
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x16,0x9A};
        // guarantees the first 4 characters, when base58 encoded, are "ZiVK"
        base58Prefixes[ZCVIEWING_KEY]      = {0xA8,0xAB,0xD3};
        // guarantees the first 2 characters, when base58 encoded, are "SK"
        base58Prefixes[ZCSPENDING_KEY]     = {0xAB,0x36};

        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "zs";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "zviews";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "zivks";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-main";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
                ( 0, consensus.hashGenesisBlock)
                (2500, uint256S("0x0002f67a10f7e44772c823b1c814e90df17d69bb7cfe07689118993a5627ba36"))
                (5000, uint256S("0x0000007dfb44c8174bdb6298a919d86067cd1ce9bc99f99720bcb32b0f4ae868"))
                (10000, uint256S("0x00017aed2440e9c6d2dc98a022c11200034fdcb2cf2fca9dc6d3be38f0791581"))
                (30000, uint256S("0x0000e03c7a6848f46b2fd5864b686aa2773a44d4b7365f0cb1444344ec3a4c7d"))
                (45000, uint256S("0x0002116dd75aad4ea470ccd9e487a3991e576e42c41cf9bc725e3313cdbaeb44"))
                (84000, uint256S("0x000003bfc909af2d71ed8a4b6f184987a36220f430282603ddcbac19a7529dfe"))
                (100000, uint256S("0x00001ced49203b79421a66d1bd2a2d9fe9afa93615a25b78cbae647cf673bdaa"))
                (150000, uint256S("0x000468d914d76a1cc59a555eb32a5d7a9845e3013e246001a214829fd89f9cba"))
                (170000, uint256S("0x0002c3b60f64bd4517cd0fe992595a6af9598ef768959dc6eeec1f06090248d6"))
                (200000, uint256S("0x00000a0f39edc929eca105fbef1916d27e59e5f122c68647607de8f25d3428b4"))
                (300000, uint256S("0x0001ba19d5089535d7bf228c90d39e453ff1a186e177553c53a3366e463efcb8")),
            1568993934,   // * UNIX timestamp of last checkpoint block
            456246,       // * total number of transactions between genesis and last checkpoint (the tx=... number in the SetBestChain debug.log lines)
            876           // * estimated number of transactions per day after checkpoint total number of tx / (checkpoint block height / (24 * 24))
        };

        // Hardcoded fallback value for the Sprout shielded value pool balance
        // for nodes that have not reindexed since the introduction of monitoring
        // in #2795.
        nSproutValuePoolCheckpointHeight = 520633;
        nSproutValuePoolCheckpointBalance = 22145062442933;
        fZIP209Enabled = true;
        hashSproutValuePoolCheckpointBlock = uint256S("0000000000c7b46b6bc04b4cbf87d8bb08722aebd51232619b214f7273f8460e");

        // Founders reward script expects a vector of 2-of-3 multisig addresses
        vFoundersRewardAddress = {
            "t3gGcAEAZrK8ZFTkZxNVPsU65MjdHbzBRn3", /* main-index: 1*/
            "t3Qm6EKTAevyyCz3DGoC9gHP1zhKrgin9Ky", /* main-index: 2*/
            "t3VKceXDRh7LXqVs5cAzZkDZTGfhLdUtAj7", /* main-index: 3*/
            "t3WAG1h22nDBTW5ACCGxqWCfiWBvixWGWtR", /* main-index: 4*/
            "t3V2p43aL5V6qaDsWoB8jpZKmd2dJQToRGD", /* main-index: 5*/
            "t3RLiouTXNFadEZAH9JF4XgWsoLmZGimjrh", /* main-index: 6*/
            "t3bPfH1ZJeYYHmGFdv8189nFp3m35nguJif", /* main-index: 7*/
            "t3cUjHmV1V2hMrkwKpvPXG5oeCjMrBy1w5s", /* main-index: 8*/
            "t3g5xFGmV2DFAtDcgb7uhwzmyXfi8vXEvea", /* main-index: 9*/
            "t3bAT5XJhQEmNVNDbTpjoSdr3tbpQgoPKfa", /* main-index: 10*/
            "t3XpSQZRwmUcQ5FYWGA8f7EPiLwg3tMfEEX", /* main-index: 11*/
            "t3LYVsmMUKj6ghxeNUhPZky6pkJj3itzKXr", /* main-index: 12*/
            "t3a4qfcWQfZGxrfn8JDybMg6hLHDkQwBQzB", /* main-index: 13*/
            "t3VN7fRBQCsci1Sy45U6SaAGjXVdAdNpBKh", /* main-index: 14*/
            "t3LGKDS2hydsQtaAGbbM9Xdg3enyaHvMTtc", /* main-index: 15*/
            "t3XjUDesUTNu6BpWHuVpQ74Ptke1PTKwh11", /* main-index: 16*/
            "t3KicwAdUEiA8y762SVZVeCZeQbQsZgrgqy", /* main-index: 17*/
            "t3eEMT4Jx7MCDBDE21kUUh3SU7gurg4wjci", /* main-index: 18*/
            "t3ZPeEnjUFXzYfdPgSGW6kyvEMB4buuPXfD", /* main-index: 19*/
            "t3YnA8GTXb2ehB61GA74qiiaQo3F246tGfA", /* main-index: 20*/
            "t3PVvtwQBTnWY8F1KVryty26B32u589Vc8D", /* main-index: 21*/
            "t3d1NdVjSB7iQ3KnMsNgfqbuUyXHQH2o7Qj", /* main-index: 22*/
            "t3XGAZswvVJ617nrEByrEsieLD8WB245KPy", /* main-index: 23*/
            "t3QjiBpXNQC77P243zyRNdJiF5eWBSN1L5L", /* main-index: 24*/
            "t3ZRJk7hXmRyZhN7UxjEMF3JhxUKYiWsBi7", /* main-index: 25*/
            "t3S8VNV38NiP7B2btXBB7aLZP7oAtdQjHU2", /* main-index: 26*/
            "t3bdJqKGd7gECWcCv1CE474Buf4VhxqeELo", /* main-index: 27*/
            "t3U4jH1CfYEqvojA3A99hZXa5a1dJjEvxzK", /* main-index: 28*/
            "t3fnnjBr4K8v35Y9svw8NxZZq9niHMZy7eT", /* main-index: 29*/
            "t3W65fDBY7nz9JYykHbP1NCP5VRMXARxarM", /* main-index: 30*/
            "t3YLqUYZmmnrRirwcPeqTyM825qP1JoiFS8", /* main-index: 31*/
            "t3Q7c8aYwC6in2bddNW2LARN14NUJyRnD16", /* main-index: 32*/
            "t3XQBGG5W7qDRWGWHN7ZaaSQ4PVfko76A62", /* main-index: 33*/
            "t3euX5fYYJwt2kYeYPXc1vBpgqe28tVtXrS", /* main-index: 34*/
            "t3hXVsaiyd5vn36ASLnAiGvJ34s8r1kXPu9", /* main-index: 35*/
            "t3ZcAgok17hCQi3aDHMgMw9rLLfzVvJmpjT", /* main-index: 36*/
            "t3Uig6wbU8w4kzYWcHsvwrW3rUytcf4usP2", /* main-index: 37*/
            "t3YF1mzsSPyainKSx8DQiprmAy7ovy6sxDU", /* main-index: 38*/
            "t3LmGWzC52Q4iK4qJwP5jeVr1QBx6cvPNNS", /* main-index: 39*/
            "t3MGBWCwyerSigxiwKuPKrFtRbXvzWkAj9x", /* main-index: 40*/
            "t3TKGtfKk9hHJ1p5PVWKgkuKKoPC44P34xw", /* main-index: 41*/
            "t3SjDKHdZXfiuBGYeA1yY4ub8ifzibRVvgo", /* main-index: 42*/
            "t3K5F1ZZY3CspL5EenEKivgDYxL9v9jTvDz", /* main-index: 43*/
            "t3af5FWx9TXENbEb12MCUagM7M2QW5K2j3s", /* main-index: 44*/
            "t3g1PwcEjKfQ9onikXVLSSJD8EYSfgZuaFj", /* main-index: 45*/
            "t3e5s7W5vYnGetPeFnU8ud3bdQmnqAJQQEb", /* main-index: 46*/
            "t3ZUo4mjogTEEJKZfe3MDCzE5kABU2PAKJv", /* main-index: 47*/
            "t3WpmC7Vhwog8G7ZaxsxA1xsN7wR8XT8Adr", /* main-index: 48*/
            "t3LHTHV743KseUiEgxnnXe5LANGvyCeVpsL", /* main-index: 49*/
            "t3SNhsh3qTisJbNkH1NAfvZg41bS5Sg5gJF", /* main-index: 50*/
//            "t3eFdihU5JqAHBpHrimhZc9gzPX4BKRFxhJ", /* main-index: 51*/
//            "t3MJ2RSjf3VgzFh6JFvBshGkqM4Dr6w2pR8", /* main-index: 52*/
//            "t3fJw4XsZKydyZi9iVE2USXyFekHVZvQ8f6", /* main-index: 53*/
//            "t3acUAmhzVhpxTEoSXLuCFUywdWqwXQGWAY", /* main-index: 54*/
//            "t3dx4r8L1QB2LahTighVxs7cvuvD3WXho52", /* main-index: 55*/
//            "t3QyaLMMArizt5zy726rW7iw38bbZpRM8nD", /* main-index: 56*/
//            "t3QsiG2B6FkkxcyBhk3vv4KbFZAzUHrxcEr", /* main-index: 57*/
//            "t3eVVbe1HWQWcS2r4aD9HSv5CWHnJAed8qv", /* main-index: 58*/
//            "t3PmqHEwm7m5KzjotfgqLTVWNZgZc5QSzcc", /* main-index: 59*/
//            "t3eiZEwg3MwuNETPyCj7QhziWVRw9xhEmYi", /* main-index: 60*/
//            "t3S8tAT2ifcutge4iHhdY7W1c3yu3JKUa8v", /* main-index: 61*/
//            "t3h83rWPx6FPw2cUQKE3TvwaQ7ZbabqZLPV", /* main-index: 62*/
//            "t3ZLCGDGSRqfFxrjjGdBua8Uu5Nor425q67", /* main-index: 63*/
//            "t3c7ksfWG6a779NsU6xhmqCMQtW93t8fEt5", /* main-index: 64*/
//            "t3NyRNoH2s5yVhkCBkZ6Q5JNLApTXiACLv8", /* main-index: 65*/
//            "t3RpwTYsBoReWqAdQe8222T91wbAuhJmeZZ", /* main-index: 66*/
//            "t3hRNQmv3rtjUj5knP7fCs3C4mLGZkc2C8i", /* main-index: 67*/
        };
        assert(vFoundersRewardAddress.size() <= consensus.GetLastFoundersRewardBlockHeight(0));
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        strCurrencyUnits = "TAS";
        bip44CoinType = 1;
        consensus.fCoinbaseMustBeProtected = false;
        consensus.nSubsidySlowStartInterval = 0;
        consensus.nPreBlossomSubsidyHalvingInterval = Consensus::PRE_BLOSSOM_HALVING_INTERVAL;
        consensus.nPostBlossomSubsidyHalvingInterval = Consensus::POST_BLOSSOM_HALVING_INTERVAL;
        consensus.nMajorityEnforceBlockUpgrade = 51;
        consensus.nMajorityRejectBlockOutdated = 75;
        consensus.nMajorityWindow = 400;
        const size_t N = 144, K = 5;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        consensus.nEquihashN = N;
        consensus.nEquihashK = K;

        eh_epoch_1 = eh200_9;
        eh_epoch_2 = eh144_5;
        eh_epoch_1_endblock = 13322;
        eh_epoch_2_startblock = 13322;

        consensus.powLimit = uint256S("07ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 32; // 32% adjustment down
        consensus.nPowMaxAdjustUp = 16; // 16% adjustment up
        consensus.nPreBlossomPowTargetSpacing = Consensus::PRE_BLOSSOM_POW_TARGET_SPACING;
        consensus.nPostBlossomPowTargetSpacing = Consensus::POST_BLOSSOM_POW_TARGET_SPACING;
        consensus.nPowAllowMinDifficultyBlocksAfterHeight = 149400;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nActivationHeight =
            Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nProtocolVersion = 170018;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nActivationHeight = Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
//        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].hashActivationBlock =
//            uint256S("0000257c4331b098045023fcfbfa2474681f4564ab483f84e4e1ad078e4acf44");
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nProtocolVersion = 170020;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight = Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
//        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].hashActivationBlock =
//            uint256S("000420e7fcc3a49d729479fb0b560dd7b8617b178a08e9e389620a9d1dd6361a");
        consensus.vUpgrades[Consensus::UPGRADE_BLOSSOM].nProtocolVersion = 170022;
        consensus.vUpgrades[Consensus::UPGRADE_BLOSSOM].nActivationHeight = Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
//        consensus.vUpgrades[Consensus::UPGRADE_BLOSSOM].hashActivationBlock =
//            uint256S("00367515ef2e781b8c9358b443b6329572599edd02c59e8af67db9785122f298");

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000001dbb4c4224");

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0x1a;
        pchMessageStart[2] = 0xf9;
        pchMessageStart[3] = 0xbf;
        vAlertPubKey = ParseHex("044611f69ad5cb991cd7dc76ddff88557bde07bb2f171bb036debb441353ffa26d3110fc07b8ffb7dffe9b0b459c30c7aac9daac5e278c6f51ebc0d292ccbbc9d6");
        nDefaultPort = 18086;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(
            1527360769,
            uint256S("0x000000000000000000000000000000000000000000000000000000000000001f"),
            ParseHex("004a9480d062bb6d7ec40037bdd18615b122daab4e22ceffa2a95b4d33a18d125f9e68a45e01bcb89cb207bfa72dd70c19dce94b782189c9aa3a8f0df76d415f994d8516e5e9e1987729e0afe1b0faa7c1da22b10f057f9ac50e9ee8ee02c17a836ee0553223d7b7301fb0a9e13ea48e9da2b3e52de6c75635f530fba13b1e8454301bc9ad6548af727654e360a6c8aa17e7b75ea56cc5b063cea33a4b864a6f6f943f55021d716f00ec9256ba8c75f99d79a1edc01a65ce304a554fc8132c6e0e83e328516264495b0a79ea6e7a099403ef0dedc085bdcaecffeee4d54f6ad6ec11a13915d37921e95622f15f70a36a15e27f80e21111aba25098eb091c4c334ef2f5c7ff56e12cdfe6a4b906bb33b5e43e118f675115e02db86f56e5fde396bebaa559827c27362feb9fdbb60d40dcda5172d5cfdae041bc772c291993d004646fa9950504cf33fa7449e22a9debde00c34809c84887a5420b63401c7331769e4bf95cac2075e5c5c6c9544ca1c3a4f73d51df9ab646bc1a350edc52165354aa12f6c0f665f0cdfc664eb7331df0113fd8c85531ea99d357418c9853a980cebddb9a16076f7cee8b6b5e35d516724a4c1e79625363b2db6a386c261f5aecd9398352f5c7504c0949dcd1fcf1060f7c96dd068d599c9ccfe1b1278db761f63c72fd5d141a77b6595db59f4f5416b7645d5b69e2f74f52400864e7161203d55a9f4da1c916e5a8810f2c5ff2c41b9487d64a28904fa43ea89c9758a27e8860fb1ade09f1f6a18b629f874c2110a878f4a04848442ac41768f9146e81a729a99cd4669516de8ac255c9b338ab0a656b4dbecbc8de89ac71e19d3ec4d985cd3120a836d45d320997a56dad8eec4d7e67221fa4313d5cab11907aba3f282e857de983477859bb8ddeb3511c0a2ba2ec9ffce6aaa1c1b33369fde821554890dcbbe2006d5133efdc6fd3ab04c0e0c119a0faaca619bac015e92484138f53e5cb14c6009f7beeaa0892d270c218d79d2393eaf1b189f75481f2ad5a1dd270103acf1d55e8fda76b492f8911071f16fb415e7157f9790c0318f2cc830c70e0e46682394d21c9ed8b3e3f17e757901da431bb4b69dcdd66c8cd435bcdcb84dd54c242b41493b913d4f9c2e5e73727fb639ae77e7e0f2f5c6be4cdacae5787bf8be5e4a8cd30cdd789952b4e06ec4aee4e6d0557ea0c9a04a56bd6b29b73797d900f665617a3c6e653d26ed1222ca34ebef7f9bab2100ad7c8d2369a401950b7da8c09fa67d2f99efb7fa50e16e1e481cc7d12dc7d336db55fc8def90878cdad245232f385e49e03b30537dddfe09b9af56679f32d60677f675b2db849978a46571af942afd0f59ea4be2d851dba4261c2bb7116486484df53f7a090fead1d302c8cc9a25d9475f34e74ed76ad600e48203792e407a7793960099f19ee0a1233fb7fa8a8cd7b3451ca248592b908108422ebcdc398075fe325e87959965b39bd0656db1c471155630895d5731956699854c6fc5112ff80935da2358ea0bb35d2dece5b74d4bfba970d1096df32dfd4a9a17041ef48ad9bb0efc47e56770d2d8557328689356177665bb677fbf620b158f244105e8f8ebbcc34271425c2c739b75e0ab4031be50a26381b827a1ff981bc46433e02e4bdae170f318e6f0aec37dfc59bad0f8e859279357f59d5c01a37c654172efbfe1319c58cd449237d785de6223896da4e260d3c1d48ec4dde39e1d1343e1424cc468ed03f2bdb18c9ba151827a499b0ed53674d3535d4ef789c377a0dec020bfc4cf96dd929250518d9201dc6a76eae160e9c3c23aa718149ba84078fbac077f9f78e3598f3107106081be346ebecfc13d5a447d9424345f6c0033fa2b63f95e2165b1f7798cd1ed75c663a5757f3a9"),
            0x2007ffff, 4, 0);

        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x004637063fc77812beccba106a36787c93738ff263dfa5397e860049dfb7db9a"));
        assert(genesis.hashMerkleRoot == uint256S("0xdf6fc210ea76d364af851fd7ce5479f717cb8f4a1a4e577f15722933b532875b"));

        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.push_back(CDNSSeedData("asofe.org", "dnsseed.testnet.asofe.org"));

        // guarantees the first 2 characters, when base58 encoded, are "tm"
        base58Prefixes[PUBKEY_ADDRESS]     = {0x1D,0x25};
        // guarantees the first 2 characters, when base58 encoded, are "t2"
        base58Prefixes[SCRIPT_ADDRESS]     = {0x1C,0xBA};
        // the first character, when base58 encoded, is "9" or "c" (as in Bitcoin)
        base58Prefixes[SECRET_KEY]         = {0xEF};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04,0x35,0x87,0xCF};
        base58Prefixes[EXT_SECRET_KEY]     = {0x04,0x35,0x83,0x94};
        // guarantees the first 2 characters, when base58 encoded, are "zt"
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x16,0xB6};
        // guarantees the first 4 characters, when base58 encoded, are "ZiVt"
        base58Prefixes[ZCVIEWING_KEY]      = {0xA8,0xAC,0x0C};
        // guarantees the first 2 characters, when base58 encoded, are "ST"
        base58Prefixes[ZCSPENDING_KEY]     = {0xAC,0x08};

        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "ztestsapling";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "zviewtestsapling";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "zivktestsapling";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-test";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;


        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
                ( 0, consensus.hashGenesisBlock)
                (2500, uint256S("0x00390ee15e3ed441663a2f13c98bfe7d7a9931149103d194d02bd571d3b9da4b"))
                (5000, uint256S("0x0027cfb0afc7471056b096bfedbe79a536ae859a5f5c0114df50ceb3c19695c8"))
                (10000, uint256S("0x001eb45924d269768f7880d3e08c1aed96d8b62eb20365dc394191634d2cb7bf"))
                (30000, uint256S("0x000a65a73546732a4ff230aeed8bff75fe00ef3211e646ce8bd1675311c6f708"))
                (45000, uint256S("0x0000a29126074cfd48823b41db1cfbdc65aabbf917c071658469c5082de720dd"))
                (100000, uint256S("0x0025f8e94b6440765d8b984467201c6d2ef633a557a43a8bde15045903b1f7ef")),
            1562255877,   // * UNIX timestamp of last checkpoint block
            134010,       // * total number of transactions between genesis and last checkpoint
                          // (the tx=... number in the SetBestChain debug.log lines)
            772           // total number of tx / (checkpoint block height / (24 * 24))
        };

        // Hardcoded fallback value for the Sprout shielded value pool balance
        // for nodes that have not reindexed since the introduction of monitoring
        // in #2795.
        nSproutValuePoolCheckpointHeight = 440329;
        nSproutValuePoolCheckpointBalance = 40000029096803;
        fZIP209Enabled = false;
        hashSproutValuePoolCheckpointBlock = uint256S("000a95d08ba5dcbabe881fc6471d11807bcca7df5f1795c99f3ec4580db4279b");

        // Founders reward script expects a vector of 2-of-3 multisig addresses
        vFoundersRewardAddress = {
            "t2AE7wYYbGBsCy2k5uQ98pEXCejfrtYMsE2", "t2FXXRJzp8tTdQ7eZYgy6eBDenLGt8kd4S8", "t2NKtdd3E5n4qfTSGqdqJkJdE3WhXehMvpy", "t2LHCNw3PJ9iUsaTGYYoPhUFRzVuhXazpVL",
            "t2NatsPSF7DjBgAjpVynyrPi7uLroZTNKJQ", "t2Fhxh4rMrz4tWySJWrooF46K2Ubvbqp6oK", "t2MeSZuou85MdzqN1mmwjnpb94KttngBKvA", "t29PNzZWKXzrfs9MGEWQbsStgTbw6WBJaQ3",
            "t2JXHvxR97tuKcc6t8gTuytZnBu7cqCMvSA", "t2SW68j2C3tKfoLvQKcmWpKVnJgUcbgqxcu", "t2RFjpco9XQFFnY4BAiEKCxSF9WJar8XdBR", "t2FZ9xN7uqrXM4t5VucbUXpAsbVGnuWH4Do",
            "t2Q8WdkiHMh56TX8CMLcW7Q7LGvhBwe7z9x", "t2KG8eaXfrBRHva9h7qVBctM1fYrjDMcB1r", "t2AfNSGTYLhQhKZgHNUXUyHPeeGxNGnNrET", "t2T7w7oqF4YGJ75UWyxjte6fmzVcFbkzU7S",
            "t28EzeaTP1GEZJxLdLNkqCEqH6fHTzRLHRA", "t28u2miwRRbF8cbSYqzy3UF5qbWZKHXMtud", "t2DxQhrQkZj8DLX3nRTRuiQVEXphA8BfdRY", "t2UxHJnaFqbj4DsMcWvWD1faBjBwvHT6tib",
            "t27in9sVwn3B8DhPAF1mSR1v3uuxYekyvDi", "t2UdVhDKV3vbUeNcz9CwVtv6Cxt6kJFC5oB", "t2A3jMJw8zF1unXaSxZRP7Mc1ffb9a6HLHB", "t2LVg6DHhz93riry8pCUVixxTEkcYp7MpXJ",
            "t2RDFYvdY5jWyuKEbKMhgxexyb1wMvscVJv", "t2HYjZdPqCqKY6986jiBXwgpbphQ4r1yYLi", "t2LYCfke6LmvfwYfJeTfXhY9zQ39X8CD9jM", "t2MFrMwVcmM2Yfqbmavv1oy3NkM8rtXMPib",
            };
        assert(vFoundersRewardAddress.size() <= consensus.GetLastFoundersRewardBlockHeight(0));
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        strCurrencyUnits = "REG";
        bip44CoinType = 1;
        consensus.fCoinbaseMustBeProtected = false;
        consensus.nSubsidySlowStartInterval = 0;
        consensus.nPreBlossomSubsidyHalvingInterval = Consensus::PRE_BLOSSOM_REGTEST_HALVING_INTERVAL;
        consensus.nPostBlossomSubsidyHalvingInterval = Consensus::POST_BLOSSOM_REGTEST_HALVING_INTERVAL;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        const size_t N = 48, K = 5;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        consensus.nEquihashN = N;
        consensus.nEquihashK = K;

        eh_epoch_1 = eh200_9;
        eh_epoch_2 = eh144_5;
        eh_epoch_1_endblock = 1;
        eh_epoch_2_startblock = 1;

        consensus.powLimit = uint256S("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
        consensus.nPowAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 0; // Turn off adjustment down
        consensus.nPowMaxAdjustUp = 0; // Turn off adjustment up
        consensus.nPreBlossomPowTargetSpacing = Consensus::PRE_BLOSSOM_POW_TARGET_SPACING;
        consensus.nPostBlossomPowTargetSpacing = Consensus::POST_BLOSSOM_POW_TARGET_SPACING;
        consensus.nPowAllowMinDifficultyBlocksAfterHeight = 0;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nActivationHeight =
            Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nProtocolVersion = 170018;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nProtocolVersion = 170020;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_BLOSSOM].nProtocolVersion = 170022;
        consensus.vUpgrades[Consensus::UPGRADE_BLOSSOM].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        pchMessageStart[0] = 0xaa;
        pchMessageStart[1] = 0xe8;
        pchMessageStart[2] = 0x3f;
        pchMessageStart[3] = 0x5f;
        nDefaultPort = 18344;
        nPruneAfterHeight = 1000;
        genesis = CreateGenesisBlock(
            1296688602,
            uint256S("0x0000000000000000000000000000000000000000000000000000000000000009"),
            ParseHex("01936b7db1eb4ac39f151b8704642d0a8bda13ec547d54cd5e43ba142fc6d8877cab07b3"),
            0x200f0f0f, 4, 0);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x733004c9c3731f0f4ccf19d77544ee624b9664c334ae787280bbad84cf9bf873"));
        assert(genesis.hashMerkleRoot == uint256S("df6fc210ea76d364af851fd7ce5479f717cb8f4a1a4e577f15722933b532875b"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of ( 0, consensus.hashGenesisBlock),
            genesis.nTime,
            0,
            0
        };

        // These prefixes are the same as the testnet prefixes
        base58Prefixes[PUBKEY_ADDRESS]     = {0x1D,0x25};
        base58Prefixes[SCRIPT_ADDRESS]     = {0x1C,0xBA};
        base58Prefixes[SECRET_KEY]         = {0xEF};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04,0x35,0x87,0xCF};
        base58Prefixes[EXT_SECRET_KEY]     = {0x04,0x35,0x83,0x94};
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x16,0xB6};
        base58Prefixes[ZCVIEWING_KEY]      = {0xA8,0xAC,0x0C};
        base58Prefixes[ZCSPENDING_KEY]     = {0xAC,0x08};

        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "zregtestsapling";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "zviewregtestsapling";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "zivkregtestsapling";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-regtest";

        // Founders reward script expects a vector of 2-of-3 multisig addresses
        vFoundersRewardAddress = { "t2FwcEhFdNXuFMv1tcYwaBJtYVtMj8b1uTg" };
        assert(vFoundersRewardAddress.size() <= consensus.GetLastFoundersRewardBlockHeight(0));
    }

    void UpdateNetworkUpgradeParameters(Consensus::UpgradeIndex idx, int nActivationHeight)
    {
        assert(idx > Consensus::BASE_SPROUT && idx < Consensus::MAX_NETWORK_UPGRADES);
        consensus.vUpgrades[idx].nActivationHeight = nActivationHeight;
    }

    void UpdateRegtestPow(int64_t nPowMaxAdjustDown, int64_t nPowMaxAdjustUp, uint256 powLimit)
    {
        consensus.nPowMaxAdjustDown = nPowMaxAdjustDown;
        consensus.nPowMaxAdjustUp = nPowMaxAdjustUp;
        consensus.powLimit = powLimit;
    }

    void SetRegTestZIP209Enabled() {
        fZIP209Enabled = true;
    }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams &Params(CBaseChainParams::Network network) {
    switch (network) {
        case CBaseChainParams::MAIN:
            return mainParams;
        case CBaseChainParams::TESTNET:
            return testNetParams;
        case CBaseChainParams::REGTEST:
            return regTestParams;
        default:
            assert(false && "Unimplemented network");
            return mainParams;
    }
}

void SelectParams(CBaseChainParams::Network network) {
    SelectBaseParams(network);
    pCurrentParams = &Params(network);

    // Some python qa rpc tests need to enforce the coinbase consensus rule
    if (network == CBaseChainParams::REGTEST && mapArgs.count("-regtestprotectcoinbase")) {
        regTestParams.SetRegTestCoinbaseMustBeProtected();
    }

    // When a developer is debugging turnstile violations in regtest mode, enable ZIP209
    if (network == CBaseChainParams::REGTEST && mapArgs.count("-developersetpoolsizezero")) {
        regTestParams.SetRegTestZIP209Enabled();
    }
}

bool SelectParamsFromCommandLine()
{
    CBaseChainParams::Network network = NetworkIdFromCommandLine();
    if (network == CBaseChainParams::MAX_NETWORK_TYPES)
        return false;

    SelectParams(network);
    return true;
}


// Block height must be >0 and <=last founders reward block height
// Index variable i ranges from 0 - (vFoundersRewardAddress.size()-1)
std::string CChainParams::GetFoundersRewardAddressAtHeight(int nHeight) const {
    int preBlossomMaxHeight = consensus.GetLastFoundersRewardBlockHeight(0);
    // zip208
    // FounderAddressAdjustedHeight(height) :=
    // height, if not IsBlossomActivated(height)
    // BlossomActivationHeight + floor((height - BlossomActivationHeight) / BlossomPoWTargetSpacingRatio), otherwise
    bool blossomActive = consensus.NetworkUpgradeActive(nHeight, Consensus::UPGRADE_BLOSSOM);
    if (blossomActive) {
        int blossomActivationHeight = consensus.vUpgrades[Consensus::UPGRADE_BLOSSOM].nActivationHeight;
        nHeight = blossomActivationHeight + ((nHeight - blossomActivationHeight) / Consensus::BLOSSOM_POW_TARGET_SPACING_RATIO);
    }
    assert(nHeight > 0 && nHeight <= preBlossomMaxHeight);
    size_t addressChangeInterval = (preBlossomMaxHeight + vFoundersRewardAddress.size()) / vFoundersRewardAddress.size();
    size_t i = nHeight / addressChangeInterval;
    return vFoundersRewardAddress[i];
}

// Block height must be >0 and <=last founders reward block height
// The founders reward address is expected to be a multisig (P2SH) address
CScript CChainParams::GetFoundersRewardScriptAtHeight(int nHeight) const {
    assert(nHeight > 0 && nHeight <= consensus.GetLastFoundersRewardBlockHeight(nHeight));

    CTxDestination address = DecodeDestination(GetFoundersRewardAddressAtHeight(nHeight).c_str());
    assert(IsValidDestination(address));
    assert(boost::get<CScriptID>(&address) != nullptr);
    CScriptID scriptID = boost::get<CScriptID>(address); // address is a boost variant
    CScript script = CScript() << OP_HASH160 << ToByteVector(scriptID) << OP_EQUAL;
    return script;
}

std::string CChainParams::GetFoundersRewardAddressAtIndex(int i) const {
    assert(i >= 0 && i < vFoundersRewardAddress.size());
    return vFoundersRewardAddress[i];
}

void UpdateNetworkUpgradeParameters(Consensus::UpgradeIndex idx, int nActivationHeight)
{
    regTestParams.UpdateNetworkUpgradeParameters(idx, nActivationHeight);
}

void UpdateRegtestPow(int64_t nPowMaxAdjustDown, int64_t nPowMaxAdjustUp, uint256 powLimit) {
    regTestParams.UpdateRegtestPow(nPowMaxAdjustDown, nPowMaxAdjustUp, powLimit);
}

int validEHparameterList(EHparameters *ehparams, unsigned long blockheight, const CChainParams& params){
  //if in overlap period, there will be two valid solutions, else 1.
  //The upcoming version of EH is preferred so will always be first element
  //returns number of elements in list
  if(blockheight >= params.eh_epoch_2_start() && blockheight > params.eh_epoch_1_end()){
    ehparams[0] = params.eh_epoch_2_params();
    return 1;
  }
  if(blockheight < params.eh_epoch_2_start()){
    ehparams[0] = params.eh_epoch_1_params();
    return 1;
  }
  ehparams[0] = params.eh_epoch_2_params();
  ehparams[1] = params.eh_epoch_1_params();
  return 2;
}
