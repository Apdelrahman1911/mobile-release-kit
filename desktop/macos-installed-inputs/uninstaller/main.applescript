-- Uninstall Mobile Release Kit (#83, OD-05c).
-- Removal itself is the unchanged signed Remove.pkg run by the standard macOS
-- Installer. This app only asks which kind of uninstall is wanted and, after
-- removal is confirmed, deletes the app's own per-user data when (and only
-- when) the user explicitly chose that and confirmed it a second time.

-- No top-level properties or globals: an applet saves those back into its own
-- bundle when it quits, and this signed app runs from a read-only image.

use framework "Foundation"
use scripting additions

on run
	set appTitle to "Uninstall Mobile Release Kit"
	try
		set {package, script_} to removalPaths()
	on error
		display dialog "The removal files for this app were not found. Open the complete Mobile Release Kit Remove disk image and run the uninstaller from there." buttons {"OK"} default button "OK" with title appTitle with icon stop
		return
	end try
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

	display dialog "Installer will now open to remove Mobile Release Kit. Follow its steps and enter an administrator password when asked." & return & return & ¬
		"When Installer finishes, quit Installer to return here." buttons {"Cancel", "Continue"} default button "Continue" cancel button "Cancel" with title appTitle with icon note
	try
		do shell script "/usr/bin/open -W -a Installer " & quoted form of package
	end try

	set checkOnly to " --check-removal"
	if deleteData then set checkOnly to ""
	-- The cleanup command checks the completion report itself. Run it once
	-- and carry its real status into the result dialog after Installer exits.
	try
		set report to do shell script "/bin/sh " & quoted form of script_ & checkOnly & " 2>&1; echo \"status=$?\""
		set lines_ to paragraphs of report
		set completion to last item of lines_
	on error
		set completion to "status=unknown"
		set lines_ to {}
	end try
	activate
	if completion is "status=65" then
		if deleteData then
			display dialog "Mobile Release Kit is still installed, so none of your data was deleted." & return & return & ¬
				"If Installer was cancelled or reported a problem, you can run this uninstaller again." buttons {"OK"} default button "OK" with title appTitle with icon caution
		else
			display dialog "Mobile Release Kit is still installed. If Installer was cancelled or reported a problem, you can run this uninstaller again." buttons {"OK"} default button "OK" with title appTitle with icon caution
		end if
		return
	end if
	if completion is "status=66" or completion is "status=64" then
		display dialog "Mobile Release Kit removal could not be confirmed. Your data was kept." & return & return & ¬
			"Check macOS Installer for the result before trying another operation." buttons {"OK"} default button "OK" with title appTitle with icon caution
		return
	end if
	if completion is not "status=0" and (not deleteData or completion is not "status=1") then
		display dialog "Mobile Release Kit could not confirm the uninstaller result." & return & return & ¬
			"Check the result in macOS Installer before trying again." buttons {"OK"} default button "OK" with title appTitle with icon caution
		return
	end if

	if not deleteData then
		display dialog "Mobile Release Kit was removed. Your data was kept." buttons {"OK"} default button "OK" with title appTitle with icon note
		return
	end if

	if completion is "status=0" then
		display dialog "Mobile Release Kit was removed and its data was deleted." buttons {"OK"} default button "OK" with title appTitle with icon note
	else
		display dialog "Mobile Release Kit was removed, but some data was kept." & return & return & retainedDetails(lines_) ¬
			buttons {"OK"} default button "OK" with title appTitle with icon caution
	end if
end run

on removalPaths()
	-- Resolve both paths from this executable's bundle. AppleScript aliases
	-- can resolve to a different mounted copy with the same bundle ID.
	set runningBundle to current application's NSBundle's mainBundle()
	set volumeURL to runningBundle's bundleURL()'s URLByDeletingLastPathComponent()
	set package to (volumeURL's URLByAppendingPathComponent:"Remove.pkg" isDirectory:false)'s |path|() as text
	set script_ to (runningBundle's resourceURL()'s URLByAppendingPathComponent:"delete-data.sh" isDirectory:false)'s |path|() as text
	repeat with itemPath in {package, script_}
		set originalPath to quoted form of (contents of itemPath)
		do shell script "/bin/test -f " & originalPath & " && /bin/test ! -L " & originalPath
	end repeat
	return {package, script_}
end removalPaths

on retainedDetails(lines_)
	set summary to ""
	set total to 0
	repeat with entry in lines_
		set detail to contents of entry
		if detail starts with "kept " or detail starts with "could not delete:" then
			set total to total + 1
			if total is less than or equal to 4 then set summary to summary & detail & return
		end if
	end repeat
	if total is greater than 4 then set summary to summary & "Additional items kept: " & (total - 4) & return
	return summary & "You can run the uninstaller again."
end retainedDetails
