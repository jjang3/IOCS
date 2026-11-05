/*
 * Copyright (C) 2004-2021 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */
 
/*
 *  This file contains an ISA-portable PIN tool for tracing memory accesses.
 */

#include <errno.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <iostream>
#include <fstream>
#include <set>
#include <stack>
#include <string>

#include "pin.H"
 
using namespace std;

using std::cerr;
using std::endl;

#define DBG_FLAG 1

FILE* trace;
 
 /* global values */
uintptr_t offset_addr;

static stack<const char*> unwindStack;
static stack<const char*> routineStack;
static stack<ADDRINT> addressStack;

#if 1
void callUnwinding(ADDRINT callrtn_addr, char *dis, ADDRINT ins_addr)
{
	PIN_LockClient();
	RTN callRtn = RTN_FindByAddress(callrtn_addr);
	if (RTN_Valid(callRtn))
	{
		auto routineName = RTN_Name(callRtn);
		string pltName = "@plt";
		
		//cerr << routineName << endl;
		if(!(strstr(routineName.c_str(),pltName.c_str()))){
			unwindStack.push(RTN_Name(callRtn).c_str());
			addressStack.push(ins_addr);
		}
		else{
			routineStack.push(RTN_Name(callRtn).c_str());
			
			addressStack.push(ins_addr);
		}
		//	return;
		RTN_Open(callRtn);
		#if DBG_FLAG
		cerr << hex << ins_addr << " [*] " << RTN_Name(callRtn) << endl;
		#endif
		RTN_Close(callRtn);
	}
	// taintSrc = false;
	PIN_UnlockClient();
}

VOID getMetadata(IMG img, void *v)
{
	#if DBG_FLAG
	printf("Loading %s, Image id = %d \n", IMG_Name(img).c_str(), IMG_Id(img));
	#endif
	ADDRINT imgEntry         	= IMG_Entry(img);
	// Global pointer (GP) of image, if a GP is used to address global data
	ADDRINT imgGlobalPt			= IMG_Gp(img);
	ADDRINT imgLoadOffset    	= IMG_LoadOffset(img);
	ADDRINT imgLowAddr    		= IMG_LowAddress(img);
	ADDRINT imgHighAddr   		= IMG_HighAddress(img);
	ADDRINT imgStartAddr  		= IMG_StartAddress(img);
	USIZE imgSizeMapping      	= IMG_SizeMapped(img);
	bool isMainExecutable       = IMG_IsMainExecutable(img);
	if (isMainExecutable == true)
	{
		#if DBG_FLAG
		printf ("   image_entry         = 0x%zx \n",imgEntry);
		printf ("   image_globalPointer = 0x%zx \n",imgGlobalPt);
		printf ("   image_loadOffset    = 0x%zx \n",imgLoadOffset);
		printf ("   image_lowAddress    = 0x%zx \n",imgLowAddr);
		printf ("   image_highAddress   = 0x%zx \n",imgHighAddr);
		printf ("   image_startAddress  = 0x%zx \n",imgStartAddr);
		printf ("   image_sizeMapped    = %lu \n",imgSizeMapping);
		#endif
		offset_addr = (uintptr_t)(imgLoadOffset);
		#if 1
		for (SYM sym = IMG_RegsymHead(img); SYM_Valid(sym); sym = SYM_Next(sym))
		{
			string undFuncName = PIN_UndecorateSymbolName(SYM_Name(sym), UNDECORATION_NAME_ONLY);
			RTN rtn = RTN_FindByAddress(imgLoadOffset + SYM_Value(sym));
			#if DBG_FLAG
			//const char* UndecoratedFuncName = PIN_UndecorateSymbolName(SYM_Name(sym), UNDECORATION_NAME_ONLY).c_str();
			//cerr << "[*] " << hex << "0x" << RTN_Address(rtn) << "\t" << undFuncName << endl;
			#endif
			#if 1
			if (RTN_Valid(rtn))
			{	
				RTN_Open(rtn);
				// For each instruction of the routine
				for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
				{
					string *instString = new string(INS_Disassemble(ins));
					if (INS_IsDirectCall(ins))
					{
						INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)callUnwinding, IARG_BRANCH_TARGET_ADDR, IARG_PTR, instString->c_str(), IARG_INST_PTR, IARG_END);
					}
				}
				RTN_Close(rtn);
			}
			#endif
		}
		#endif
	}
}
#endif

// Print a memory read record
VOID RecordMemRead(CONTEXT *ctxt, VOID* ip, VOID* addr) { 
    fprintf(trace, "%p: R %p\n", ip, addr); 
    // cerr << "R " << std::hex << addr << endl;
}
 
// Print a memory write record
VOID RecordMemWrite(CONTEXT* ctx, VOID* ip, VOID* addr, REG reg, ADDRINT disp) { 
    ADDRINT val;
    PIN_GetContextRegval(ctx, reg, reinterpret_cast<UINT8 *>(&val));
    if (REG_valid(reg)) {
        auto reg_name = REG_StringShort(REG_FullRegName(reg));
        if (reg_name == "rsp") {
            cerr << "W " << std::hex << addr << " " << val << " " << disp << endl;
        }
    }
    // cerr << "W " << std::hex << addr << endl;
    fprintf(trace, "%p: W %p\n", ip, addr); 
    
}
 
// Is called for every instruction and instruments reads and writes
VOID Instruction(INS ins, VOID* v)
{
    // Instruments memory accesses using a predicated call, i.e.
    // the instrumentation is called iff the instruction will actually be executed.
    //
    // On the IA-32 and Intel(R) 64 architectures conditional moves and REP
    // prefixed instructions appear as predicated instructions in Pin.
    UINT32 memOperands = INS_MemoryOperandCount(ins);
 
    // Iterate over each memory operand of the instruction.
    for (UINT32 memOp = 0; memOp < memOperands; memOp++)
    {
        if (INS_MemoryOperandIsRead(ins, memOp))
        {
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordMemRead, IARG_INST_PTR, IARG_MEMORYOP_EA, memOp,
                                     IARG_END);
        }
        // Note that in some architectures a single memory operand can be
        // both read and written (for instance incl (%eax) on IA-32)
        // In that case we instrument it once for read and once for write.
        if (INS_MemoryOperandIsWritten(ins, memOp))
        {
            REG b_reg = INS_OperandMemoryBaseReg(ins, memOp);
            ADDRINT disp = INS_OperandMemoryDisplacement(ins, memOp);
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWrite, IARG_CONTEXT, IARG_INST_PTR, IARG_MEMORYOP_EA, memOp, IARG_UINT64, b_reg,
            IARG_ADDRINT, disp, IARG_END);
        }
    }
}
 
VOID Fini(INT32 code, VOID* v)
{
    fprintf(trace, "#eof\n");
    fclose(trace);
}
 
/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */
 
INT32 Usage()
{
    PIN_ERROR("This Pintool prints a trace of memory addresses\n" + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}
 
/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */
 
int main(int argc, char* argv[])
{
    /* initialize symbol processing */
	PIN_InitSymbols();
	
    if (PIN_Init(argc, argv)) return Usage();

	trace = fopen("dft.out", "w");
	if (trace != NULL)
	{
		//printf("Success\n");
		//fprintf(trace, "Output file\n");
	}
 
	IMG_AddInstrumentFunction(getMetadata, 0);
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);
 
    // Never returns
    PIN_StartProgram();
 
    return 0;
}