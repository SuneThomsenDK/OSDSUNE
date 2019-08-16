.SYNOPSIS

	Create nice Windows 10 toast notifications for the logged on user in Windows.

.DESCRIPTION

	Everything is customizeable through config-toast.xml.
	Config-toast.xml can be locally or set to an UNC path with the -Config parameter.
	This way you can quickly modify the configuration without the need to push new files to the computer running the toast.
	Can be used for improving the numbers in Windows Servicing as well as kindly reminding users of pending reboots.
	All actions are logged to a local log file in programdata\ToastNotification\New-Toastnotificaion.log.

.PARAMETER Config
 
	Specify the path for the config.xml. If none is specificed, the script uses the local config.xml

.NOTES

	Filename: New-ToastNotification.ps1
	Version: 1.2
	Author: Martin Bengtsson
	Blog: www.imab.dk
	Twitter: @mwbengtsson

    Version history:
    	1.0
		script created
    	1.1
		Separated checks for pending reboot in registry/WMI from OS uptime.
		More checks for conflicting options in config.xml.
		The content of the config.xml is now imported with UTF-8 encoding enabling other characters to be used in the text boxes.
		1.2
		Added option for personal greeting using given name retreived from Active Directory. If no AD available, the script will use a placeholder.
		Added ToastReboot protocol example, enabling the toast to carry out a potential reboot.

	2019-08-16 Modified by @SuneThomsenDK
	OSDSune https://www.osdsune.com/home/blog/2019/splash-screen-driver-bios-update
		Added:
		 - Multi language support
		 - Several text variables in XML

		Changed:
		 - Date formatting
		 - All text can now be edited directly in the XML file for multi language purpose

		Removed:
		 - 

.LINKS

	https://www.imab.dk/windows-10-toast-notification-script/
