# Yet another Windows 10 pocket antispy script
***Helps you to get rid of all Windows 10 bloatware and resolve privacy issues***

Current version performs following cleanups:
* Disable all Telemetry and data-collecting services in Service Control Manager
* Disable data-collecting tasks in Windows Scheduler
* Block all traffic to all known MS Telemetry servers
* Disable Cortana
* Remove any Metro bloatware

## Disable Telemetry
Calling the script with the key `windows_10_antispy.py --disable-telemetry` disables services and policies related to MS 
Telemetry, and also disables Scheduler tasks starting Telemetry-related applications and services

If it's not enough for you, you can `windows_10_antispy.py --block-telemetry-traffic`. This effectively blocks all traffic 
to all known MS Telemetry-related services. 
I should notice, MS insists that these changes may harm your system, 
however testing shows no any problem with Windows work.

## Disable Cortana
Cortana is a source of irritation of many Windows users, it may start consuming your CPU 
or write insane amount of some data to your disk. 
Simply stopping the Cotrana process through the Task Manager does not help much, 
Runtime Broker, manager of Metro applications, would start it again in 1-2 seconds.

However, running  `windows_10_antispy.py --disable-cortana` makes it stop forever by renaming the directory, 
containing Cortana executable before Runtime Broker starts it again.

## Remove Metro bloatware
Windows 10 comes with insanely irritating amount of applications, from games to Sticky Notes, 
and without any chance to decline its during the system installation. Luckily, the script offers several options, which help you to get rid of any of them, in fact all of them if you feel that need.

### Uninstall "default list"
Running the script with the key `windows_10_antispy.py --uninstall-bloatware` performs uninstalling of some reasonable 
"default" set of Metro applications, releasing some amount of your disk drive and leaves the system 
in absolutely working state, because there are no really useful applications there. Here's the list:

* MicrosoftEdge
* ContentDeliveryManager
* CloudExperienceHost
* Win32WebViewHost
* XboxGameCallableUI
* SecureAssessmentBrowser
* SecHealthUI
* PeopleExperienceHost
* XGpuEjectDialog
* ParentalControls
* NarratorQuickStart
* BioEnrollment
* Wallet
* WebpImageExtension
* XboxSpeechToTextOverlay
* Advertising.Xaml
* MicrosoftEdgeDevToolsClient
* GetHelp
* ZuneMusic
* ScreenSketch
* Appconnector
* People
* HEIFImageExtension
* WebMediaExtensions
* Messaging
* VP9VideoExtensions
* Photos
* XboxIdentityProvider
* Cortana
* XboxGameOverlay
* MicrosoftStickyNotes
* XboxApp
* MSPaint
* XboxGamingOverlay
* WindowsMaps
* WindowsSoundRecorder
* 3DBuilder
* WindowsAlarms
* windowscommunicationsapps
* WindowsCalculator
* Microsoft3DViewer

### Choose which Metro applications to uninstall

Your preferences may be different than mine, so you may want to choose which Metro applications to uninstall 
and which to keep using. Here you need to perform two steps.

First, run the script with the key, listing all Metro applications, and redirect its output to file
`windows_10_antispy.py --list-bloatware > metro_apps.txt`

You will find the list something like provided it above, but a bit longer. You can edit the file `metro_apps.txt`,
**leaving** applications which you want to uninstall, and **deleting** which you want to keep using.

After you finished with the file, you can run the script providing the file name with the key 
`windows_10_antispy.py --uninstall-from-file metro_apps.txt` and enjoy your cleaned up Windows 10