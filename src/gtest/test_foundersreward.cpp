#include <gtest/gtest.h>

#include "main.h"
#include "utilmoneystr.h"
#include "chainparams.h"
#include "utilstrencodings.h"
#include "zcash/Address.hpp"
#include "wallet/wallet.h"
#include "amount.h"
#include <memory>
#include <string>
#include <set>
#include <vector>
#include <boost/filesystem.hpp>
#include "util.h"
#include "utiltest.h"

// To run tests:
// ./zcash-gtest --gtest_filter="founders_reward_test.*"

//
// Enable this test to generate and print 48 testnet 2-of-3 multisig addresses.
// The output can be copied into chainparams.cpp.
// The temporary wallet file can be renamed as wallet.dat and used for testing with zcashd.
//
#if 0
TEST(founders_reward_test, create_testnet_2of3multisig) {
    SelectParams(CBaseChainParams::TESTNET);
    boost::filesystem::path pathTemp = boost::filesystem::temp_directory_path() / boost::filesystem::unique_path();
    boost::filesystem::create_directories(pathTemp);
    mapArgs["-datadir"] = pathTemp.string();
    bool fFirstRun;
    auto pWallet = std::make_shared<CWallet>("wallet.dat");
    ASSERT_EQ(DB_LOAD_OK, pWallet->LoadWallet(fFirstRun));
    pWallet->TopUpKeyPool();
    std::cout << "Test wallet and logs saved in folder: " << pathTemp.native() << std::endl;
    
    int numKeys = 48;
    std::vector<CPubKey> pubkeys;
    pubkeys.resize(3);
    CPubKey newKey;
    std::vector<std::string> addresses;
    for (int i = 0; i < numKeys; i++) {
        ASSERT_TRUE(pWallet->GetKeyFromPool(newKey));
        pubkeys[0] = newKey;
        pWallet->SetAddressBook(newKey.GetID(), "", "receive");

        ASSERT_TRUE(pWallet->GetKeyFromPool(newKey));
        pubkeys[1] = newKey;
        pWallet->SetAddressBook(newKey.GetID(), "", "receive");

        ASSERT_TRUE(pWallet->GetKeyFromPool(newKey));
        pubkeys[2] = newKey;
        pWallet->SetAddressBook(newKey.GetID(), "", "receive");

        CScript result = GetScriptForMultisig(2, pubkeys);
        ASSERT_FALSE(result.size() > MAX_SCRIPT_ELEMENT_SIZE);
        CScriptID innerID(result);
        pWallet->AddCScript(result);
        pWallet->SetAddressBook(innerID, "", "receive");

        std::string address = EncodeDestination(innerID);
        addresses.push_back(address);
    }
    
    // Print out the addresses, 4 on each line.
    std::string s = "vFoundersRewardAddress = {\n";
    int i=0;
    int colsPerRow = 4;
    ASSERT_TRUE(numKeys % colsPerRow == 0);
    int numRows = numKeys/colsPerRow;
    for (int row=0; row<numRows; row++) {
        s += "    ";
        for (int col=0; col<colsPerRow; col++) {
            s += "\"" + addresses[i++] + "\", ";
        }
        s += "\n";
    }
    s += "    };";
    std::cout << s << std::endl;

    pWallet->Flush(true);
}
#endif


static int GetLastFoundersRewardHeight(const Consensus::Params& params) {
    int blossomActivationHeight = Params().GetConsensus().vUpgrades[Consensus::UPGRADE_BLOSSOM].nActivationHeight;
    bool blossom = blossomActivationHeight != Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
    return params.GetLastFoundersRewardBlockHeight(blossom ? blossomActivationHeight : 0);
}

// Utility method to check the number of unique addresses from height 1 to maxHeight
void checkNumberOfUniqueAddresses(int nUnique) {
    std::set<std::string> addresses;
    for (int i = 1; i <= GetLastFoundersRewardHeight(Params().GetConsensus()); i++) {
        addresses.insert(Params().GetFoundersRewardAddressAtHeight(i));
    }
    EXPECT_EQ(addresses.size(), nUnique);
}


TEST(founders_reward_test, general) {
    SelectParams(CBaseChainParams::TESTNET);

    CChainParams params = Params();
    
    // Fourth testnet reward:
    // address = t2ENg7hHVqqs9JwU5cgjvSbxnT2a9USNfhy
    // script.ToString() = OP_HASH160 55d64928e69829d9376c776550b6cc710d427153 OP_EQUAL
    // HexStr(script) = a91455d64928e69829d9376c776550b6cc710d42715387
    EXPECT_EQ(HexStr(params.GetFoundersRewardScriptAtHeight(1)), "a914ef775f1f997f122a062fff1a2d7443abd1f9c64287");
    EXPECT_EQ(params.GetFoundersRewardAddressAtHeight(1), "t2UNzUUx8mWBCRYPRezvA363EYXyEpHokyi");
    EXPECT_EQ(HexStr(params.GetFoundersRewardScriptAtHeight(53126)), "a914ac67f4c072668138d88a86ff21b27207b283212f87");
    EXPECT_EQ(params.GetFoundersRewardAddressAtHeight(53126), "t2NGQjYMQhFndDHguvUw4wZdNdsssA6K7x2");
    EXPECT_EQ(HexStr(params.GetFoundersRewardScriptAtHeight(53127)), "a91455d64928e69829d9376c776550b6cc710d42715387");
    EXPECT_EQ(params.GetFoundersRewardAddressAtHeight(53127), "t2ENg7hHVqqs9JwU5cgjvSbxnT2a9USNfhy");

    int maxHeight = GetLastFoundersRewardHeight(params.GetConsensus());
    
    // If the block height parameter is out of bounds, there is an assert.
    EXPECT_DEATH(params.GetFoundersRewardScriptAtHeight(0), "nHeight");
    EXPECT_DEATH(params.GetFoundersRewardScriptAtHeight(maxHeight+1), "nHeight");
    EXPECT_DEATH(params.GetFoundersRewardAddressAtHeight(0), "nHeight");
    EXPECT_DEATH(params.GetFoundersRewardAddressAtHeight(maxHeight+1), "nHeight"); 
}

TEST(founders_reward_test, regtest_get_last_block_blossom) {
    int blossomActivationHeight = Consensus::PRE_BLOSSOM_REGTEST_HALVING_INTERVAL / 2; // = 75
    auto params = RegtestActivateBlossom(false, blossomActivationHeight);
    int lastFRHeight = params.GetLastFoundersRewardBlockHeight(blossomActivationHeight);
    EXPECT_EQ(0, params.Halving(lastFRHeight));
    EXPECT_EQ(1, params.Halving(lastFRHeight + 1));
    RegtestDeactivateBlossom();
}

TEST(founders_reward_test, mainnet_get_last_block) {
    SelectParams(CBaseChainParams::MAIN);
    auto params = Params().GetConsensus();
    int lastFRHeight = GetLastFoundersRewardHeight(params);
    EXPECT_EQ(0, params.Halving(lastFRHeight));
    EXPECT_EQ(1, params.Halving(lastFRHeight + 1));
}

#define NUM_MAINNET_FOUNDER_ADDRESSES 48

TEST(founders_reward_test, mainnet) {
    SelectParams(CBaseChainParams::MAIN);
    checkNumberOfUniqueAddresses(NUM_MAINNET_FOUNDER_ADDRESSES);
}


#define NUM_TESTNET_FOUNDER_ADDRESSES 48

TEST(founders_reward_test, testnet) {
    SelectParams(CBaseChainParams::TESTNET);
    checkNumberOfUniqueAddresses(NUM_TESTNET_FOUNDER_ADDRESSES);
}


#define NUM_REGTEST_FOUNDER_ADDRESSES 1

TEST(founders_reward_test, regtest) {
    SelectParams(CBaseChainParams::REGTEST);
    checkNumberOfUniqueAddresses(NUM_REGTEST_FOUNDER_ADDRESSES);
}



// Test that 10% founders reward is fully rewarded after the first halving and slow start shift.
// On Mainnet, this would be 2,100,000 ZEC after 850,000 blocks (840,000 + 10,000).
TEST(founders_reward_test, slow_start_subsidy) {
    SelectParams(CBaseChainParams::MAIN);
    CChainParams params = Params();

    CAmount totalSubsidy = 0;
    for (int nHeight = 1; nHeight <= GetLastFoundersRewardHeight(Params().GetConsensus()); nHeight++) {
        CAmount nSubsidy = GetBlockSubsidy(nHeight, params.GetConsensus()) / 5;
        totalSubsidy += nSubsidy;
    }
    
    ASSERT_TRUE(totalSubsidy == MAX_MONEY/10.0);
}


// For use with mainnet and testnet which each have 48 addresses.
// Verify the number of rewards each individual address receives.
void verifyNumberOfRewards() {
    CChainParams params = Params();
    int maxHeight = GetLastFoundersRewardHeight(params.GetConsensus());
    std::map<std::string, CAmount> ms;
    for (int nHeight = 1; nHeight <= maxHeight; nHeight++) {
        std::string addr = params.GetFoundersRewardAddressAtHeight(nHeight);
        if (ms.count(addr) == 0) {
            ms[addr] = 0;
        }
        ms[addr] = ms[addr] + GetBlockSubsidy(nHeight, params.GetConsensus()) / 5;
    }

    EXPECT_EQ(ms[params.GetFoundersRewardAddressAtIndex(0)], 1960039937500);
    EXPECT_EQ(ms[params.GetFoundersRewardAddressAtIndex(1)], 4394460062500);
    for (int i = 2; i <= 46; i++) {
        EXPECT_EQ(ms[params.GetFoundersRewardAddressAtIndex(i)], 17709 * COIN * 2.5);
    }
    EXPECT_EQ(ms[params.GetFoundersRewardAddressAtIndex(47)], 17677 * COIN * 2.5);
}

// Verify the number of rewards going to each mainnet address
TEST(founders_reward_test, per_address_reward_mainnet) {
    SelectParams(CBaseChainParams::MAIN);
    verifyNumberOfRewards();
}

// Verify the number of rewards going to each testnet address
TEST(founders_reward_test, per_address_reward_testnet) {
    SelectParams(CBaseChainParams::TESTNET);
    verifyNumberOfRewards();
}
