#ifndef USERMODEHOOK_TEB_TEB_H_
#define USERMODEHOOK_TEB_TEB_H_

#define NtCurrentPeb()     (PPEB)(NtCurrentTeb()->ProcessEnvironmentBlock)

#endif