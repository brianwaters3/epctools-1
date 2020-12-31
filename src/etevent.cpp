/*
* Copyright (c) 2009-2019 Brian Waters
* Copyright (c) 2019 Sprint
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#include "etevent.h"
#include "einternal.h"
#include "esignal.h"

/// @cond DOXYGEN_EXCLUDE

EThreadTimerError_UnableToInitialize::EThreadTimerError_UnableToInitialize()
{
   setSevere();
   setTextf("%s: Error initializing timer - ", Name());
   appendLastOsError();
}

EThreadTimerError_NotInitialized::EThreadTimerError_NotInitialized()
{
   setSevere();
   setTextf("%s: Error timer not initialized - ", Name());
}

EThreadTimerError_AlreadyInitialized::EThreadTimerError_AlreadyInitialized()
{
   setSevere();
   setTextf("%s: Error timer has already been initialized - ", Name());
}

EThreadTimerError_UnableToStart::EThreadTimerError_UnableToStart()
{
   setSevere();
   setTextf("%s: Error starting timer - ", Name());
   appendLastOsError();
}

EThreadTimerError_UnableToRegisterTimerHandler::EThreadTimerError_UnableToRegisterTimerHandler()
{
   setSevere();
   setTextf("%s: Error registering timer handler - ", Name());
   appendLastOsError();
}

Long EThreadEventTimer::m_nextid = 0;
int EThreadEventTimer::m_signo = ETHREADTIMER_SIGNAL;

static EThreadEventTimerHandler _initTimerHandler;

Void EThreadEventTimerHandler::init(EGetOpt &options)
{
   options.setPrefix(SECTION_TOOLS "/" SECTION_SIGNALS);
   EThreadEventTimer::setSignal(options.get(MEMBER_SIGNALS_THREADTIMER, ETHREADTIMER_SIGNAL));
   options.setPrefix("");

   struct sigaction sa;
   sa.sa_flags = SA_SIGINFO;
   sa.sa_sigaction = EThreadEventTimer::_timerHandler;
   sigemptyset(&sa.sa_mask);
   int signo = EThreadEventTimer::getSignal();
   if (sigaction(signo, &sa, NULL) == -1)
      throw EThreadTimerError_UnableToRegisterTimerHandler();
}

Void EThreadEventTimerHandler::uninit()
{
}

/// @endcond
