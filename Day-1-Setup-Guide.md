# Project ATLAS — Day 1 Walkthrough: Build the Lab

Goal for today: a Windows 11 ARM64 "victim" VM that can talk to Kali and to the internet, with Sysmon installed and forwarding telemetry into a Sentinel workspace via Azure Arc + the Azure Monitor Agent, plus Defender for Cloud turned on in Azure. ~2.5–3.5 hours (this got longer than the original plan — see the note at the top of Part F for why).

This replaces two things from the original blueprint that were wrong/overcomplicated — noted inline below so you know why.

**📸 Screenshots:** every step below marked with a camera icon is a documentation checkpoint — capture it now, even though the GitHub writeup comes later. On your Mac, create a folder `Project-ATLAS-Screenshots/Day1/` and save each one with a short numbered name as you go (e.g. `01-efi-boot-menu.png`, `02-oobe-bypass.png`) so they're already in order when you build the README. Don't skip these even if a step feels routine — it's much easier to grab the shot in the moment than to recreate the scenario afterward.

---

## Part A — Download Windows 11 ARM64 (10 min)

1. Go to **https://www.microsoft.com/en-us/software-download/windows11arm64**
2. Under "Download Windows 11 Disk Image (ISO) for Arm-based PCs," select **Windows 11 (multi-edition ISO for Arm64)** from the dropdown → **Download**.
3. Pick your language → **Confirm**.
4. Click **Download Now**. The link is only valid 24 hours, so don't sit on it.

*Correction from the original blueprint:* it told you to register for the Windows Insider Program first. You don't need to — Microsoft publishes a stable ARM64 ISO directly on that page now, no sign-in or registration.

This is a "multi-edition" ISO — during install you'll pick the edition (Pro is the right call) without entering a product key. It'll run unactivated ("Activate Windows" watermark) — irrelevant for a lab that doesn't last more than a few weeks.

---

## Part B — Network design: plain NAT + port forwarding (5 min read, nothing to do yet)

*Correction from the original blueprint:* it told you to put both VMs on a fully isolated "Internal Network." That would have blocked Sentinel, Azure Arc, and the Azure Monitor Agent from ever reporting data — all three need outbound internet to phone home to Microsoft's cloud.

*Second correction, after extensive real-world testing on this exact Mac:* every VirtualBox networking mode that depends on a host-side driver or a shared virtual switch — Bridged Adapter, Internal Network, NAT Network, Host-only Adapter — either crashed the VM or returned a non-functional address. Root cause confirmed via `systemextensionsctl list` returning **0 extensions**: VirtualBox's host-networking component was never registered on this Mac, so nothing beyond plain NAT (which needs no host driver at all) works on this install.

**The fix: plain NAT, one adapter, on both VMs — plus host-side port forwarding for VM-to-VM traffic.**

Plain NAT gives each VM its own private internet connection (`10.0.2.x`, auto-assigned, no manual IP needed) with zero shared state between VMs — that's the only thing that's worked cleanly all day. The tradeoff: a VM behind plain NAT can't be reached directly by another VM, since there's no real network between them. Port forwarding fixes that: a rule on the Mac host says "anything that hits port X on this machine gets relayed into VM Y's port Z." From inside either VM, `10.0.2.2` always means "the host" — so a forwarded connection to `10.0.2.2:<port>` lands wherever the rule points.

This is exactly what Day 3's attack chain uses: Kali "scanning" and "brute-forcing" Windows means Kali connecting to `10.0.2.2:<forwarded port>`, and Windows' reverse shell calling back to `10.0.2.2:<forwarded port>` lands in a listener running on Kali. You're pre-mapping the specific ports involved instead of doing open-ended LAN discovery — a normal, explainable adjustment for a home-lab network behind NAT, worth one line in the README's scope notes.

---

## Part C — Create the Windows VM (10 min)

1. In VirtualBox Manager's main window, click **New** in the top toolbar.
2. In the **Name** field, type `Windows11-Victim`.
3. Click the folder/browse icon next to **ISO Image**.
4. Browse to and select the Windows 11 ARM64 ISO you downloaded in Part A.
5. Wait a few seconds — VirtualBox should auto-fill **Type** as "Microsoft Windows" and **Version** as "Windows 11 (64-bit ARM)" (since you're on an Apple Silicon host).
6. Check that those two fields actually populated correctly before continuing — if they're blank or wrong, re-select the ISO.
7. If you see a checkbox labeled **Skip Unattended Installation**, check it. If instead you see an "Unattended Install" section with username/password fields, ignore/leave them blank — VirtualBox's unattended installer doesn't support Arm guests, so you'll click through Windows Setup by hand in Part D. Either way is normal, not an error.
8. Click **Next**.
9. On the Hardware screen, set **Base Memory** to **8192 MB** (type the number directly or drag the slider).
10. Set **Processors** to **2–4 vCPUs** (lower if your Mac is under memory pressure with Kali also running, but don't go below 4GB RAM total or Windows 11 will struggle).
11. Click **Next**.
12. On the Virtual Hard Disk screen, leave **Create a Virtual Hard Disk Now** selected.
13. Set the disk size to **64 GB**.
14. Confirm **VDI (VirtualBox Disk Image)** and **Dynamically allocated** are selected (these are the defaults — don't change them).
15. Click **Next**.
16. On the summary screen, click **Finish**.
17. The new `Windows11-Victim` VM now appears in your VirtualBox list — **do not click Start yet.**
18. Select the `Windows11-Victim` VM in the list.
19. Click **Settings** (gear icon in the toolbar).
20. At the top of the Settings window, click **Expert** (next to **Basic**) if it isn't already selected. **Basic mode hides Internal Network and the Adapter 2–4 tabs** — it only offers NAT and Bridged Adapter, which is why you may not see the option you need later today. Expert mode reveals everything; nothing about your VM changes by switching it.
21. Click **Network** in the left-hand settings menu.
22. On the **Adapter 1** tab, find the **Attached to** dropdown.
23. Change it to **Not attached**.
24. Click **OK** to save and close Settings.

---

## Part D — Install Windows 11 (20–30 min, mostly waiting)

1. Select `Windows11-Victim` in VirtualBox Manager and click **Start**.
2. **ARM64 VMs boot through EFI firmware, not the classic BIOS prompt.** So instead of "Press any key to boot from CD or DVD," you'll most likely land directly on a gray-and-black text menu titled with options like `Continue`, `Reset`, `Boot Manager`, `Device Manager`, `Boot Maintenance Manager`, and a "Select Language" line. **This is normal** — it's VirtualBox's built-in EFI firmware front page, not an error, even though nothing on it mentions Windows yet.
   - If you see a RAM figure (e.g. "0 MB") printed on this screen, ignore it — it's a known cosmetic quirk of this firmware page and doesn't reflect your actual configured memory (8192 MB from Part C).
   - 📸 **Screenshot:** this EFI firmware menu — a good "behind the scenes" shot showing the ARM64-specific boot process most x86 guides never cover.
3. Using the **arrow keys** (this menu doesn't respond to mouse clicks), move the highlight down to **Boot Manager**.
4. Press **Enter**.
5. A list of boot devices appears. Look for an entry referencing the optical drive — something like `UEFI VBOX CD-ROM VB-xxxxxxxx-xxxxxxxx`. Don't select "Built-in EFI Shell" or anything saying "Hard Disk" yet — the disk is still empty at this point.
6. Highlight the CD-ROM entry and press **Enter**.
7. One of two things happens next: Windows Setup starts loading files directly, or you briefly see "Press any key to boot from CD or DVD." If you see that message, press a key on your keyboard immediately (within ~5 seconds) — if you miss the window, it times out and drops you back at the firmware menu from step 2, and you just repeat steps 3–6.
8. Wait for the Windows Setup screen to load.
9. Choose your language, time/currency format, and keyboard layout from the dropdowns.
10. Click **Next**.
11. Click **Install Now**.
12. On the "Activate Windows" screen, click **I don't have a product key** (small link near the bottom).
13. From the edition list, select **Windows 11 Pro**.
14. Click **Next**.
15. Check the box to accept the license terms.
16. Click **Next**.
17. Choose **Custom: Install Windows only (advanced)**.
18. Select the only listed virtual disk (it'll show as unallocated space).
19. Click **Next**.
20. Wait — Windows copies files and reboots the VM automatically one or more times. This takes 10–20 minutes.
    - **Watch for the EFI firmware menu reappearing during this step.** Unlike a BIOS VM, EFI doesn't always remember to boot the disk automatically after a mid-install reboot. If you land back on the `Continue` / `Boot Manager` / `Device Manager` screen from step 2, go to **Boot Manager** again — but this time select the entry referencing the **hard disk** (e.g. `UEFI VBOX HARDDISK VB-xxxxxxxx-xxxxxxxx`), not the CD-ROM. Picking the CD-ROM again at this stage would restart Setup from scratch instead of continuing the in-progress install.
21. When you reach **"Let's connect you to a network,"** you will most likely **not** see an "I don't have internet" link at all — Windows only shows that link when it detects a network adapter but no connection. Since Part C set the adapter to "Not attached," Windows detects no adapter at all, so this screen instead shows just an **"Install driver"** button and "Having trouble getting connected?" text. That's expected, not a problem.
22. Click inside the VM window to make sure it has focus, then press **Shift + F10**. A black Command Prompt window opens on top of the network screen.
23. Type `start ms-cxh:localonly` and press **Enter**. (This is the command confirmed working as of mid-2026 — Microsoft has repeatedly added and removed different OOBE bypass commands, so if this exact one does nothing, close the prompt, press Shift+F10 again, and instead try `oobe\bypassnro` followed by Enter — that one may restart the VM back into OOBE with the "I don't have internet" link now visible, which you'd then click followed by "Continue with limited setup.")
   - 📸 **Screenshot:** this Command Prompt with the command visible, before closing it — documents the OOBE network-bypass technique.
24. If a Command Prompt window is still open, type `exit` and press **Enter** to close it.
25. You should now be on (or have been returned to) the local-account creation screen — continue below.
26. On "Who's going to use this device," type a username (e.g. your first name).
27. Click **Next**.
28. Create a password, then confirm it in the next field.
29. Set up the three required security questions (mandatory even for local accounts) and click **Next** after each.
30. On each remaining privacy/OOBE screen (location, Find My Device, diagnostic data, advertising ID, etc.), leave the default toggle and click **Accept** or **Next**.
31. Wait for "This might take several minutes" to finish — you'll land on the desktop automatically.
32. Switch back to the VirtualBox Manager window (the VM keeps running in the background — e.g. Cmd+Tab on the Mac host, or click the VirtualBox icon).
33. With `Windows11-Victim` still selected and running, click **Settings** — VirtualBox allows changing the network type on a running VM.
34. Click **Network** in the left menu.
35. On the **Adapter 1** tab, change **Attached to** from "Not attached" to **NAT**.
36. Click **OK**.
37. Switch back into the Windows VM window.
38. Open **Command Prompt** (search `cmd` in the Start menu, press Enter) and run `ipconfig`.
39. Confirm you see an **IPv4 Address** starting with `10.0.2.` — that's the NAT adapter working automatically, no manual IP needed.
   - 📸 **Screenshot:** this `ipconfig` output — proof the VM has a working, internet-routable adapter.
40. Open **Microsoft Edge** (pinned to the taskbar, or search "Edge" from the Start menu).
41. Type any address, e.g. `bing.com`, and press Enter.
42. If the page doesn't load within ~15 seconds, restart the VM (Start menu → Power → Restart), let it reach the desktop, and try again.
   - 📸 **Screenshot:** Edge with the page loaded — proof the VM has working internet.
43. In the VirtualBox menu bar (not inside Windows), click **Machine**.
44. Click **Take Snapshot**.
45. Name it `clean-install`.
46. Click **OK**. This is your rollback point — if anything breaks later (onboarding script, network), you restore here instead of reinstalling.
   - 📸 **Screenshot:** the VM's Snapshots tab showing `clean-install` — shows operational discipline (rollback points), worth a line in the README.
47. Shut down the VM cleanly: inside Windows, **Start → Power → Shut down**. Port-forwarding rules (next step) can only be added while a VM is powered off.
48. Once VirtualBox Manager shows `Windows11-Victim` as **Powered Off**, open Terminal on your Mac and run these one at a time:
    ```
    VBoxManage modifyvm "Windows11-Victim" --natpf1 "rdp,tcp,,33389,,3389"
    VBoxManage modifyvm "Windows11-Victim" --natpf1 "smb,tcp,,33445,,445"
    VBoxManage modifyvm "Windows11-Victim" --natpf1 "winrm,tcp,,35985,,5985"
    ```
    No output means each one worked. These forward host ports 33389/33445/35985 into Windows' RDP/SMB/WinRM ports — Day 3's Nmap/Hydra steps target these, since plain NAT means Kali can only reach ports you've explicitly mapped (see Part B).
49. Select `Windows11-Victim` and click **Start** again to bring it back up for the rest of today's steps.

---

## Part E — Put Kali on the same network (5 min)

1. If Kali is currently running, shut it down first: inside Kali, click the power icon (top right) → **Shut Down** — or, from VirtualBox Manager, right-click the Kali VM → **Close** → **Send the shutdown signal**.
2. Once Kali is powered off, select it in VirtualBox Manager and click **Settings**.
3. Click **Network** in the left menu.
4. On the **Adapter 1** tab, confirm **Attached to** shows **NAT** (set it if it doesn't — same single-adapter plain NAT as Windows; see Part B for why).
5. If a second adapter is enabled from earlier troubleshooting, click the **Adapter 2** tab and uncheck **Enable Network Adapter** — not needed.
6. Click **OK**.
7. Open Terminal on your Mac and first confirm the VM's exact registered name — VirtualBox names can include a trailing space that isn't visible in the Manager UI but breaks every `VBoxManage` command using the name in quotes:
   ```
   VBoxManage list vms
   ```
   Copy the name exactly as printed (including any trailing space inside the quotes), or just use the UUID shown next to it — the UUID has no quoting issues and is the safer option. Then run:
   ```
   VBoxManage modifyvm <exact-name-or-UUID> --natpf1 "revshell,tcp,,44444,,4444"
   ```
   This forwards host port 44444 into Kali's port 4444 — Day 3's reverse-shell listener sits on 4444, and Windows connects out to `10.0.2.2:44444` to reach it.
8. Select the Kali VM and click **Start**.
9. Once Kali's desktop loads, open a terminal.
10. Type `ip a` and press Enter.
11. Confirm an interface shows an `inet 10.0.2.x` address — the NAT adapter working, same as Windows.
12. Optional: `curl -s ifconfig.me` should print a public IP, confirming outbound internet.

That's it for today's network setup — no VM-to-VM ping test right now. Plain NAT intentionally isolates the two VMs except through the port-forwarding rules you just added, and those get proven for real on Day 3 when the attack chain actually uses them.

---

## Part E.1 — Reliable copy-paste setup (do this first when you resume, ~10 min)

VirtualBox's shared clipboard (Devices → Shared Clipboard → Bidirectional) doesn't reliably paste into a Linux guest terminal without Guest Additions installed, which is its own rabbit hole on this ARM64 build. Skip it entirely with these two workarounds — both use connections you've already half-built.

**Kali — SSH from your Mac's own Terminal app (native paste always works):**

Kali's UUID for this project is `96347395-4ee0-4844-a589-cf66b4324078` — used directly below instead of a placeholder (confirm anytime via `VBoxManage list vms` if you ever rebuild the VM).

1. Start Kali from its saved state. Open a terminal inside it.
2. `sudo apt update && sudo apt install -y openssh-server`
3. `sudo systemctl enable --now ssh`
4. Shut Kali down fully (not save state this time): inside Kali, **Shut Down**, or from your Mac:
   ```
   VBoxManage controlvm 96347395-4ee0-4844-a589-cf66b4324078 poweroff
   ```
5. On your Mac Terminal, add an SSH port-forward:
   ```
   VBoxManage modifyvm 96347395-4ee0-4844-a589-cf66b4324078 --natpf1 "ssh,tcp,,2222,,22"
   ```
6. ```
   VBoxManage startvm 96347395-4ee0-4844-a589-cf66b4324078
   ```
7. Once booted, from your Mac Terminal: `ssh -p 2222 ivanyamoahboakye@127.0.0.1`
8. Accept the host key prompt, enter your Kali password. You're now in Kali's shell from a native Mac Terminal window — Cmd+C / Cmd+V works normally for anything I give you.

**Windows RDP — abandoned 2026-06-20, here's why and what to do instead:**

After extensive testing (Remote Desktop enabled, NLA toggled off, port-forward confirmed open via `nc` from both the Mac and from inside Kali, tried both the Mac's Windows App and FreeRDP from Kali with correct credentials), every RDP client hit the same wall: TCP connects fine, then the connection gets reset mid-handshake (`BIO_read returned a system error 104: Connection reset by peer`, `freerdp_post_connect failed`). Since this happened identically across two completely different RDP client implementations with verified-correct credentials, the cause isn't a setting in Windows — it's this same host's VirtualBox NAT engine (the one with 0 system extensions, see Part B) mishandling RDP's longer TLS handshake the way it's mishandled every other non-trivial networking mode this project has hit. Not worth more time chasing.

**The actual fix: you don't need RDP at all.** Reframe where each task happens:
- Sentinel, Defender for Cloud, Azure portal (Parts F and G below, and all of Days 2, 4, 5) — these are cloud dashboards. Do them from **your Mac's own browser** (Safari/Chrome), logged into security.microsoft.com / portal.azure.com directly. Nothing about them requires being inside the Windows VM. Full native copy-paste, zero VM involved.
- Anything that must run physically inside the Windows VM (Day 3's attack-chain commands) — these are short enough to type by hand, or I'll drop a ready-made `.ps1`/`.bat` script into a **VirtualBox Shared Folder** (Devices → Shared Folders, no clipboard or RDP needed) for you to double-click and run.
- Kali's copy-paste is already solved — the SSH setup above works.

Skip the rest of this Windows RDP section entirely.

<details>
<summary>Original RDP steps (abandoned, kept for reference only)</summary>

**Windows — Microsoft Remote Desktop app (clipboard redirection built in, no setup inside the VM):**

0. **Do this first, inside the Windows VM itself** — Remote Desktop is off by default on Windows 11, and the port-forward rule from Part D only relays traffic, it doesn't turn the feature on. Switch to the Windows11-Victim VM window:
   - Press **Win+I** to open Settings.
   - Click **System** in the left nav.
   - Click **Remote Desktop**.
   - Toggle it **On**.
   - Click **Confirm** on the popup.
   - Leave "Require devices to use Network Level Authentication" checked (default).
   - Your local account (created in Part D) is an admin and already allowed — no extra user setup needed.

1. On your Mac, open the **App Store**.
2. Search `Windows App` (this is Microsoft's current name for what used to be "Microsoft Remote Desktop").
3. Find the one published by **Microsoft Corporation**, click **Get** (or the cloud-download icon), and let it install — it's free.
4. Click **Open** (or launch it from Launchpad).
5. On first launch it may prompt you to sign in with a Microsoft account. A direct PC connection doesn't require this — look for **Skip** or an **X** to dismiss it. If it blocks you from continuing without signing in, sign in with your Microsoft 365 admin account.
6. In the left sidebar, click **Devices** (ignore "Workspaces"/"Apps" — those are for Azure Virtual Desktop, not this).
7. Click the **+** / **Add** button (top right, or inside the Devices panel).
8. Choose **Add PC** (or **PC** if it gives you a list of connection types).
9. In the **PC name** (or **Hostname**) field, type `127.0.0.1:33389`. If the dialog instead shows separate **Hostname** and **Port** fields, put `127.0.0.1` and `33389` in each.
10. Optionally set **Friendly name** to `Windows11-Victim` so it's labeled clearly in the list.
11. Click **Save**/**Add**.
12. A new tile appears in Devices — double-click it to connect.
13. If you see a certificate warning ("identity of the remote computer cannot be verified"), click **Connect anyway** (or check "Don't ask again" first) — expected for a local lab VM, not a real risk.
14. Enter the Windows VM's local account username and password (the one you set in Part D).
15. Click **Continue**/**OK** — the Windows 11 desktop should appear inside the window.
16. Test it: copy any text on your Mac (Cmd+C), click inside the RDP window, paste (Cmd+V) — should land instantly, no Guest Additions needed.

If any screen looks different from this, send a screenshot — Microsoft renames things in this app fairly often.

Do this once and the rest of the project (Days 2–5 have heavy KQL/PowerShell copy-paste) goes much faster.

---

## Part F — Sysmon + Azure Arc + Azure Monitor Agent: building the endpoint telemetry pipeline (40–55 min)

**Why this replaced Defender for Endpoint:** Microsoft retired the standalone free trial for Defender for Endpoint Plan 2 partway through building this lab, and the tenant's billing region blocked the card-based workaround. Rather than pay for a license or stall, this pipeline rebuilds the same EDR-equivalent telemetry from scratch: Sysmon generates the process/network/logon events, Azure Arc brings this non-Azure VM under Azure's management plane, and the Azure Monitor Agent forwards Sysmon's log plus the Windows Security log into the same Sentinel workspace everything else in this project uses. It's more steps than clicking "onboard" in Defender's UI, but it's also a more direct demonstration of hybrid on-prem-to-cloud monitoring — one of the job description's core bullets.

**Note on RDP-free workflow:** steps that only touch the Azure portal (1–4, 11–12, 18–24) can be done from your Mac's browser. Steps that must run physically inside the Windows VM (5–10, 13–17, the Arc connect script and Sysmon install) — click directly into the VM's own window and use its mouse/keyboard like normal; getting the Arc script into the VM uses a VirtualBox Shared Folder (no clipboard/RDP needed), covered in step 9.

1. On your Mac (or in the VM), go to **https://portal.azure.com** and sign in with your Azure admin account.
   - 📸 Azure portal home page after sign-in.
2. In the top search bar, type `Subscriptions` → click the matching result → click your subscription's name.
3. In the left menu, click **Resource providers**. One at a time, filter for and confirm/register each of these (select the row → **Register** if it shows "NotRegistered," then wait ~1–2 min for it to flip to "Registered"):
   - `Microsoft.OperationalInsights`
   - `Microsoft.OperationsManagement`
   - `Microsoft.Security`
   - `Microsoft.HybridCompute`
   - `Microsoft.GuestConfiguration`
   - The last two are new compared to what you might expect — they're what Azure Arc needs to manage a non-Azure machine.
   - 📸 Resource providers list with all five showing **Registered**.
4. In the top search bar, type `Log Analytics workspaces` → click the matching result → **+ Create**.
   - Resource group: **Create new** → name it `rg-soc-atlas` → OK.
   - Name: `law-soc-atlas`.
   - Region: pick the one closest to you.
   - **Review + create** → **Create**. Wait for "Your deployment is complete."
   - 📸 Deployment complete notification, or the new workspace's Overview page.
5. In the top search bar, type `Servers - Azure Arc` → click the matching result → **+ Add/Create** → **Add a single server**.
6. Resource group: select `rg-soc-atlas` (created in step 4). Region: same as your workspace. Click **Next**.
7. Operating system: **Windows**. Connectivity method: **Public endpoint** (default — fine for this lab). Click **Next: Generate script**.
8. On the script-generation page, **Generate script** → **Download**. This saves `OnboardingScript.ps1`.
   - 📸 The "Generate script" page just before/after download.

   ![Azure Arc onboarding script generated](assets/screenshots/00c-azure-arc-onboarding-script.png)
9. Get this script into the Windows VM via a VirtualBox Shared Folder:
   - VirtualBox Manager → select `Windows11-Victim` → **Settings → Shared Folders → +** (Add).
   - Folder Path: browse to wherever `OnboardingScript.ps1` downloaded.
   - Check **Auto-mount** and **Make Permanent**. Click OK twice.
   - Start the VM if it isn't running. Inside Windows, open File Explorer → the shared folder appears under **Network locations** (or type `\\VBOXSVR\<foldername>` directly into the address bar).
   - Copy `OnboardingScript.ps1` from the shared folder onto the VM's desktop.
10. Right-click `OnboardingScript.ps1` on the desktop → **Run with PowerShell** (or open an elevated PowerShell window and run `.\OnboardingScript.ps1` from the Desktop).
    - 📸 The PowerShell window mid-run.

    ![Azure Arc onboarding script running inside Windows VM](assets/screenshots/00d-azure-arc-script-running-vm.png)

    - It opens a browser device-code sign-in — sign in with your Azure admin account when prompted.
    - 📸 The device-code sign-in screen (crop/blur the code itself — it expires in minutes anyway).
11. Wait for the script to finish (a "this machine is now connected to Azure Arc" or similar success message).
    - 📸 The script's final success output.
12. Back in the Azure portal, go to **Servers - Azure Arc** → confirm your machine appears with **Status: Connected**. Azure Arc registers it under its actual Windows hostname (e.g. `DESKTOP-TRF9U79`), not the VirtualBox VM name `Windows11-Victim` — those are two different namespaces.
    - 📸 **Screenshot (must-have):** the Arc-enabled server showing Connected — proof this non-Azure VM is now under Azure's management plane.
13. Inside the Windows VM, open a browser and go to **https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon** → download **Sysmon** (the zip containing `Sysmon64.exe`).
    - 📸 The Sysinternals Sysmon download page.
14. Also download a known-good config: go to **https://github.com/SwiftOnSecurity/sysmon-config** → click **sysmonconfig-export.xml** → **Download raw file**.
15. Extract the Sysmon zip, and put both `Sysmon64.exe` and `sysmonconfig-export.xml` in the same folder.
16. Open an elevated PowerShell (right-click Start → **Terminal (Admin)**), `cd` to that folder, and run:
    ```
    .\Sysmon64.exe -accepteula -i sysmonconfig-export.xml
    ```
    - 📸 The command and its "Sysmon installed" output.

    ![Sysmon service started and installed](assets/screenshots/02-sysmon-service-started.png)
17. Verify it's logging: open **Event Viewer** → **Applications and Services Logs → Microsoft-Windows-Sysmon → Operational**. You should already see events accumulating — Sysmon logs activity immediately on install.
    - 📸 Event Viewer showing Sysmon Operational events.
18. Back in the Azure portal, top search bar → type `Data Collection Rules` → click the matching result → **+ Create**.
19. **Basics tab:** Rule name `dcr-soc-atlas-sysmon`, Resource group `rg-soc-atlas`, Region matching your workspace, Platform Type **Windows**. Click **Next: Resources**.

   ![DCR creation — Basics tab](assets/screenshots/04-dcr-creation-basics.png)
20. **Resources tab:** **+ Add resources** → find and select your Arc machine by its actual hostname (e.g. `DESKTOP-TRF9U79` — filter the resource type to "Machines - Azure Arc" if it's hard to find) → **Add**. Click **Next: Collect and deliver**.
21. **Collect and deliver tab:** **+ Add data source** → Data source type: **Windows Event Logs**.
    - Leave the "Basic" checkbox list unchecked.
    - Switch to **Custom** and add these two XPath queries (as two entries if the UI only accepts one per data source):
      ```
      Microsoft-Windows-Sysmon/Operational!*
      Security!*[System[(EventID=4625)]]
      ```
    - Click **Next**.
    - 📸 The data source configuration showing both XPath queries.
22. **Destination:** **+ Add destination** → Destination type **Azure Monitor Logs** → select your subscription → select the `law-soc-atlas` workspace → **Add data source**.

   ![DCR destination configured — law-soc-atlas workspace](assets/screenshots/06-dcr-destination-law.png)

23. **Review + create** → **Create**. Wait for deployment to finish.
    - 📸 DCR deployment complete.
24. The first DCR associated with an Arc machine usually prompts Azure to install the **Azure Monitor Agent** extension automatically — accept that if prompted. If it doesn't prompt, go to your Arc machine resource (by its hostname, e.g. `DESKTOP-TRF9U79`) → **Extensions** → **+ Add** → search "Azure Monitor Agent" → install it manually.
    - 📸 Extensions list on the Arc machine showing AzureMonitorWindowsAgent as Succeeded.

    ![AMA extension installed and succeeded on Arc machine](assets/screenshots/07-ama-extension-installed.png)
25. Give it 5–15 minutes, then verify in the `law-soc-atlas` workspace (or Sentinel's Logs blade once Part G connects it) → **Logs**:
    ```kql
    Heartbeat
    | where Computer contains "DESKTOP-TRF9U79"  // your machine's actual hostname, not the VirtualBox VM name
    | take 5
    ```
    A row confirms the agent is alive and checking in.
26. Then run:
    ```kql
    Event
    | where Computer contains "DESKTOP-TRF9U79"  // your machine's actual hostname, not the VirtualBox VM name
    | where Source == "Microsoft-Windows-Sysmon"
    | take 10
    ```
    - 📸 **Screenshot (must-have):** this query returning Sysmon rows — direct evidence the custom telemetry pipeline works end to end, the centerpiece "what I actually built" shot given the licensing detour that led here.

If step 25/26 returns nothing after 20+ minutes, the likely culprit is the DCR association (step 20) or the XPath syntax (step 21) — tell me exactly what you see in the Arc machine's **Extensions** tab and the **Data Collection Rules → Associations** if so.

---

## Part G — Azure: Defender for Cloud + Sentinel (15–20 min)

Resource providers and the Log Analytics workspace are already done — Part F, steps 3–4.

1. In the top search bar, type `Microsoft Defender for Cloud` and click the matching result.
2. Click **Environment settings** in the left nav.
3. Click your subscription's name in the list.
4. Just loading this page automatically enables **Foundational CSPM** (free) — there's no toggle to click for this part.
5. Scroll through the other listed plans (Defender CSPM, Servers, Storage, Containers, etc.).
6. Confirm every one of them is switched **Off** (toggle in the left/gray position). Leave them all off — they're paid and not needed for this project.
    - 📸 **Screenshot:** this Environment settings page showing Foundational CSPM on and the paid plans off — demonstrates deliberate, cost-conscious posture management, not just "clicked everything on."
7. Open a new browser tab and go to **https://security.microsoft.com**.
8. In the left nav, click **Microsoft Sentinel** (it now lives inside the Defender portal, not a separate Azure blade — Microsoft is retiring the standalone Azure-portal Sentinel experience in July 2026).
9. If prompted to connect a workspace, click **Connect a workspace** (button wording may vary slightly).
10. Select the `law-soc-atlas` workspace you created in Part F.
11. Set it as **Primary**.
12. Click **Connect**.
13. Click **Connect** again on the confirmation prompt.
    - 📸 **Screenshot (must-have):** Sentinel showing the connected workspace — this is the centerpiece tool of the whole project; lead the README's tooling section with it.

    ![Microsoft Sentinel connected to law-soc-atlas workspace](assets/screenshots/00b-sentinel-connected-to-law.png)
14. Still inside security.microsoft.com, find the **Microsoft Sentinel** section in the left nav and click **Content management**.
15. Click **Content hub**.
16. In the search box, type `Microsoft Defender XDR`.
17. Click the matching solution tile.
18. Click **Install** (or **Deploy** if that's the label shown instead).
19. Wait for the status on that tile to change to **Installed**.
    - 📸 **Screenshot:** the tile showing **Installed** — closes out Day 1's tooling proof.

Note: Microsoft's portal wording shifts version to version — if a menu item isn't exactly where described, use the search bar at the top of the relevant portal and search the bolded term.

Note: Microsoft's portal wording shifts version to version — if a menu item isn't exactly where described, use the search bar at the top of the relevant portal and search the bolded term.

---

## End-of-day checklist

- Windows 11 ARM64 VM installed, local account, snapshot taken
- Windows VM and Kali both on plain NAT (single adapter, auto-assigned `10.0.2.x`) for internet
- Port-forward rules in place: Windows RDP/SMB/WinRM (host 33389/33445/35985 → guest 3389/445/5985), Kali reverse-shell listener (host 44444 → guest 4444) — used starting Day 3
- Windows VM shows Connected in Azure Arc; Sysmon installed and logging; DCR forwarding Sysmon + Security 4625 events into `law-soc-atlas` (confirmed via `Heartbeat`/`Event` queries)
- Log Analytics workspace created, Sentinel connected to it via security.microsoft.com
- Defender for Cloud Foundational CSPM active (paid plans left off)
- Microsoft Defender XDR solution installed from Content Hub

If you finish early, don't start Day 2 tonight unless you want to — pace per the original 5-day plan. If something's stuck (onboarding script errors, network not picking up, OOBE refusing local account), tell me exactly what's on screen and we'll fix it before moving on.
