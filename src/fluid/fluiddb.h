// Copyright (c) 2018 Duality Blockchain Solutions Developers

#ifndef FLUID_DB_H
#define FLUID_DB_H

#include "amount.h"

class CDynamicAddress;
class CFluidDynode;
class CFluidMining;
class CFluidMint;
class CFluidSovereign;

CAmount GetFluidDynodeReward();
CAmount GetFluidMiningReward();
bool GetMintingInstructions(const int nHeight, CFluidMint& fluidMint);
bool IsSovereignAddress(const CDynamicAddress& inputAddress);
bool GetAllFluidDynodeRecords(std::vector<CFluidDynode>& dynodeEntries);
bool GetAllFluidMiningRecords(std::vector<CFluidMining>& miningEntries);
bool GetAllFluidMintRecords(std::vector<CFluidMint>& mintEntries);
bool GetAllFluidSovereignRecords(std::vector<CFluidSovereign>& sovereignEntries);

#endif // FLUID_DYNODE_H