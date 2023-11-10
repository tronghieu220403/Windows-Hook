#ifndef IATHOOK_TEB_TEB_H_
#define IATHOOK_TEB_TEB_H_

#define NtCurrentPeb()     (PPEB)(NtCurrentTeb()->ProcessEnvironmentBlock)

#endif