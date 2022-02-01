## MOJO - EtwEventWrite Patcher ##

Mojo is a standalone code which simulate the patching of EtwEventWrite function within it memory.
With this technique we're preventing from within the process itself to submit new ETW Events.

The function EtwEventWrite is located within the ntdll.dll module. 

-- For now the patching functionality is ready and can be used in your PoCs, the payload is in progress for making it standalone PoC.
