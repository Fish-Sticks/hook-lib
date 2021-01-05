#pragma once
#include <Windows.h>

namespace hook
{
	struct HOOK_INFO
	{
		void* allocatedMem;
		size_t allocatedSize;

		uintptr_t start;
		uintptr_t end;
	};

	HOOK_INFO setTrampolineHook(uintptr_t startAddress, uintptr_t endAddress);
	bool removeTrampolineHook(HOOK_INFO& previous);

	HOOK_INFO setNormalHook(uintptr_t addy, uintptr_t result, size_t overwrite);
	bool removeNormalHook(HOOK_INFO& previous);
}
