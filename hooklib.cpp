#include <Windows.h>
#include <iostream>

namespace hook
{
	struct HOOK_INFO
	{
		void* allocatedMem;
		size_t allocatedSize;

		uintptr_t start;
		uintptr_t end;
	};

	HOOK_INFO setTrampolineHook(uintptr_t startAddress, uintptr_t endAddress)
	{
		HOOK_INFO ret = { 0 };
		ret.start = startAddress;
		ret.end = endAddress;

		void* allocated = VirtualAlloc(NULL, 10, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		ret.allocatedMem = allocated;
		ret.allocatedSize = 10;

		DWORD old;
		VirtualProtect(reinterpret_cast<LPVOID>(startAddress), 5, PAGE_EXECUTE_READWRITE, &old);

		memcpy(allocated, reinterpret_cast<void*>(startAddress), 5);

		*reinterpret_cast<byte*>(startAddress) = 0xE9;
		*reinterpret_cast<uintptr_t*>(startAddress + 1) = (endAddress - startAddress) - 5;

		*reinterpret_cast<byte*>(reinterpret_cast<uintptr_t>(allocated) + 5) = 0xE9;
		*reinterpret_cast<uintptr_t*>(reinterpret_cast<uintptr_t>(allocated) + 6) = startAddress - reinterpret_cast<uintptr_t>(allocated) - 5;

		VirtualProtect(reinterpret_cast<LPVOID>(startAddress), 5, old, &old);

		return ret;
	}

	bool removeTrampolineHook(HOOK_INFO& previous)
	{
		if (previous.allocatedMem && previous.allocatedSize && previous.end && previous.start) {
			if (previous.allocatedSize == 10) {
				byte* previousBytes = new byte[5];
				memcpy(previousBytes, previous.allocatedMem, 5);
				VirtualFree(previous.allocatedMem, 0, MEM_RELEASE);

				DWORD old;
				VirtualProtect(reinterpret_cast<LPVOID>(previous.start), 5, PAGE_EXECUTE_READWRITE, &old);
				memcpy(reinterpret_cast<void*>(previous.start), previousBytes, 5);
				VirtualProtect(reinterpret_cast<LPVOID>(previous.start), 5, old, &old);

				delete[] previousBytes;

				return true;
			}
		}
		return false;
	}

	HOOK_INFO setNormalHook(uintptr_t addy, uintptr_t result, size_t overwrite)
	{
		HOOK_INFO retValue;
		DWORD old;
		VirtualProtect(reinterpret_cast<LPVOID>(addy), overwrite, PAGE_EXECUTE_READWRITE, &old);

		void* overwritten = VirtualAlloc(nullptr, overwrite, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		memcpy(overwritten, reinterpret_cast<void*>(addy), overwrite);

		memset(reinterpret_cast<void*>(addy), 0x90, overwrite);
		*reinterpret_cast<byte*>(addy) = 0xE9;
		*reinterpret_cast<uintptr_t*>(addy + 1) = (result - addy) - 5;

		VirtualProtect(reinterpret_cast<LPVOID>(addy), overwrite, old, &old);

		retValue.allocatedMem = overwritten;
		retValue.allocatedSize = overwrite;
		retValue.start = addy;
		retValue.end = result;

		return retValue;
	}

	bool removeNormalHook(HOOK_INFO& previous)
	{
		if (previous.allocatedMem && previous.allocatedSize && previous.end && previous.start) {
			DWORD old;
			VirtualProtect(reinterpret_cast<LPVOID>(previous.start), previous.allocatedSize, PAGE_EXECUTE_READWRITE, &old);
			memcpy(reinterpret_cast<void*>(previous.start), previous.allocatedMem, previous.allocatedSize);
			VirtualProtect(reinterpret_cast<LPVOID>(previous.start), previous.allocatedSize, old, &old);
			VirtualFree(previous.allocatedMem, 0, MEM_RELEASE);
			return true;
		}
		return false;
	}
};
