/*
* Copyright (c) 2020 T-Mobile
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

#ifndef __ESIGHAL_H
#define __ESIGHAL_H

#ifndef ETHREADTIMER_SIGNAL
#define ETHREADTIMER_SIGNAL (SIGRTMIN)
#endif

#ifndef ETIMERPOOL_TIMER_SIGNAL
#define ETIMERPOOL_TIMER_SIGNAL (SIGRTMIN+1)
#endif

#ifndef ETIMERPOOL_QUIT_SIGNAL
#define ETIMERPOOL_QUIT_SIGNAL (SIGRTMIN+2)
#endif

#endif // #define __ESIGHAL_H