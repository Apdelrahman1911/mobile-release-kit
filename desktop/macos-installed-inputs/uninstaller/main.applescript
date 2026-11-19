-- Uninstall Mobile Release Kit (#83, OD-05c).
-- Removal itself is the unchanged signed Remove.pkg run by the standard macOS
-- Installer. This app only asks which kind of uninstall is wanted and, after
-- removal is confirmed, deletes the app's own per-user data when (and only
-- when) the user explicitly chose that and confirmed it a second time.

-- No top-level properties or globals: an applet saves those back into its own
-- bundle when it quits, and this signed app runs from a read-only image.

on run
	set appTitle to "Uninstall Mobile Release Kit"
	set keepLabel to "Uninstall App (Keep My Data)"
	set deleteLabel to "Uninstall App & Delete All Data"
	set choice to button returned of (display dialog "How do you want to uninstall Mobile Release Kit?" & return & return & ¬
		"Keep My Data (recommended): removes the app and keeps your settings, drafts, history and saved credentials, so a later reinstall continues where you left off." & return & return & ¬
		"Delete All Data: also permanently deletes that data from this Mac. Your project folders and other files are never touched." buttons {"Cancel", deleteLabel, keepLabel} default button keepLabel cancel button "Cancel" with title appTitle with icon caution)
	set deleteData to (choice is deleteLabel)
	if deleteData then
		display dialog "Delete all Mobile Release Kit data?" & return & return & ¬
			"After the app is removed, this permanently deletes its settings, drafts, history, caches and saved credentials (including its Keychain items) for your user account. This cannot be undone." & return & return & ¬
			"Your project folders, documents and other apps' files are not deleted." buttons {"Cancel", "Delete All Data"} default button "Cancel" cancel button "Cancel" with title appTitle with icon stop
	end if

	set here to POSIX path of (path to me)
	set package to do shell script "/usr/bin/dirname " & quoted form of here
	set package to package & "/Remove.pkg"
	try
		do shell script "/bin/test -f " & quoted form of package
	on error
		display dialog "Remove.pkg was not found next to this app. Open the complete Mobile Release Kit Remove disk image and run the uninstaller from there." buttons {"OK"} default button "OK" with title appTitle with icon stop
		return
	end try

	display dialog "Installer will now open to remove Mobile Release Kit. Follow its steps and enter an administrator password when asked." & return & return & ¬
		"When Installer finishes, quit Installer to return here." buttons {"Cancel", "Continue"} default button "Continue" cancel button "Cancel" with title appTitle with icon note
	try
		do shell script "/usr/bin/open -W -a Installer " & quoted form of package
	end try

	if not removed() then
		if deleteData then
			display dialog "Mobile Release Kit is still installed, so none of your data was deleted." & return & return & ¬
				"If Installer was cancelled or reported a problem, you can run this uninstaller again." buttons {"OK"} default button "OK" with title appTitle with icon caution
		else
			display dialog "Mobile Release Kit is still installed. If Installer was cancelled or reported a problem, you can run this uninstaller again." buttons {"OK"} default button "OK" with title appTitle with icon caution
		end if
		return
	end if

	if not deleteData then
		display dialog "Mobile Release Kit was removed. Your data was kept." buttons {"OK"} default button "OK" with title appTitle with icon note
		return
	end if

	set script_ to (POSIX path of (path to resource "delete-data.sh"))
	-- The script's own report goes to stdout; its exit status is appended as
	-- the last line so the report is shown whatever the outcome.
	try
		set report to do shell script "/bin/sh " & quoted form of script_ & " 2>&1; echo \"status=$?\""
	on error message
		set report to message & return & "status=error"
	end try
	set lines_ to paragraphs of report
	set outcome to "partial"
	if (last item of lines_) is "status=0" then set outcome to "complete"
	set report to ""
	if (count of lines_) > 1 then
		set AppleScript's text item delimiters to return
		set report to (items 1 thru -2 of lines_) as text
		set AppleScript's text item delimiters to ""
	end if
	if outcome is "complete" then
		display dialog "Mobile Release Kit was removed and its data was deleted." buttons {"OK"} default button "OK" with title appTitle with icon note
	else
		display dialog "Mobile Release Kit was removed, but some data was kept:" & return & return & report & return & return & ¬
			"Nothing else was deleted. You can run this uninstaller again, or delete the listed items yourself (Keychain items with Keychain Access)." buttons {"OK"} default button "OK" with title appTitle with icon caution
	end if
end run

on removed()
	set installedApp to "/Library/Application Support/MobileReleaseKit/Mobile Release Kit.app"
	try
		do shell script "/bin/test ! -e " & quoted form of installedApp & " -a ! -L " & quoted form of installedApp
		return true
	on error
		return false
	end try
end removed
