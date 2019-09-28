package gui;

import java.io.*;
import java.nio.file.Files;
import java.util.*;
import java.util.concurrent.*;
import java.util.zip.*;

import com.dd.plist.*;

public class Background implements Runnable {
    private static Background staticBackground;
    private static LinkedBlockingQueue<Device> staticDeviceQueue;
    private String ipswUrl = null;
    private NSDictionary dict = null;
    private Device device;
    private Thread thread;

    static {
        staticDeviceQueue = new LinkedBlockingQueue<>();
        staticBackground = new Background();
    }

    static LinkedBlockingQueue<Device> getQueue() {
        return staticDeviceQueue;
    }

    private Background() {
        thread = new Thread(this, "Background");
    }

    static void start() {
        if (staticBackground.thread.getState() == Thread.State.NEW) {
            staticBackground.thread.start();
        }
    }

    static String getResourceFile(String path) {
        String writtenPath = getWorkingDir() + "/" + path;
        String resName = String.format("res/%s", path);
        try (InputStream jarFile = Background.class.getResourceAsStream(resName)) {
            // Open written file in temporary directory
            try (FileOutputStream tempFile = new FileOutputStream(writtenPath)) {
                jarFile.transferTo(tempFile);
            }
        } catch (IOException e) {
            Main.error("Failed to load resource %s", resName);
            Main.exc(e);
        }
        return writtenPath;
    }

    private static String workingDir = "";

    private static String getWorkingDir() {
        if (workingDir == null) {
            try {
                workingDir = Files.createTempDirectory("ssh_rd").toAbsolutePath().toString();
            } catch (IOException e) {
                Main.error("Failed to create temporary directory");
                Main.exc(e);
                workingDir = "";
            }
        }
        return workingDir;
    }

    static String _ipswDir = null;

    static String ipswDir() {
        if (_ipswDir == null) {
            String ipswDirName = String.format("ipsw_%s_%s",
                    stringFromNsDict(staticBackground.dict, WebScraper.device),
                    stringFromNsDict(staticBackground.dict, WebScraper.build));
            _ipswDir = new File(new File(getWorkingDir()), ipswDirName).getPath();
        }
        return _ipswDir;
    }

    static String stringFromNsDict(NSDictionary nsd, String key) {
        Object o = nsd.objectForKey(key);
        if (!(o instanceof NSString)) {
            return null;
        }
        return o.toString();
    }

    Hashtable<String, String> filePropsByName(String name) {
        Hashtable<String, String> props = new Hashtable<String, String>();
        String normalizedName = name.toLowerCase();
        boolean ios5 = (null != dict.objectForKey("ios5"));
        boolean ios3 = (null != dict.objectForKey("ios3"));
        boolean ios43 = (null != dict.objectForKey("ios43"));
        String norPatch = "nor5.patch.json";
        String kernelPatch = "kernel5.patch.json";
        String wtfPatch = "wtf.patch.json";

        if (!ios5) {
            norPatch = (device.isWtf() && ios3) ? wtfPatch : device.isArmV6() ? "nor_armv6.patch.json" : "nor.patch.json";
            kernelPatch = device.isArmV6() ?
                    (ios3 ? "kernel3.patch.json" : "kernel_armv6.patch.json") :
                    ios43 ? "kernel43.patch.json" : "kernel.patch.json";
        }

        if (normalizedName.contains("kernelcache")) {
            props.put("iv", WebScraper.kernelIV);
            props.put("key", WebScraper.kernelKey);
            props.put("patch", kernelPatch);
        } else if (normalizedName.contains("ibss")) {
            props.put("iv", WebScraper.ibssIV);
            props.put("key", WebScraper.ibssKey);
            props.put("patch", norPatch);
        } else if (normalizedName.contains("ibec")) {
            props.put("iv", WebScraper.ibecIV);
            props.put("key", WebScraper.ibecKey);
            props.put("patch", norPatch);
        } else if (normalizedName.endsWith(".dmg")) {
            props.put("iv", WebScraper.ramdiskIV);
            props.put("key", WebScraper.ramdiskKey);
            props.put("ramdisk", "yes");
        } else if (normalizedName.contains("wtf")) {
            props.put("patch", wtfPatch);
        } else { // manifest, device tree, Restore.plist
            props.put("passthrough", "yes");
        }
        return props;
    }

    static boolean _payloadCreatedOk = false;
    static boolean _payloadCreationTest = false;

    static boolean _ramdiskSent = false;

    public static boolean ramdiskSent() {
        return _ramdiskSent;
    }

    private static HashSet<String> s_seen = new HashSet<String>();

    static boolean getFileFromZip(String zipUrl, String zipPath, String downloadPath) {
        boolean spamOnce = false;
        if (!s_seen.contains(zipUrl)) {
            s_seen.add(zipUrl);
            spamOnce = true;
        }
        boolean isUrl = zipUrl.toLowerCase().startsWith("http:");
        // Try local first:
        String zipName = zipUrl.substring(zipUrl.lastIndexOf('/') + 1); // not found => -1 + 1 = 0 => whole string
        File zipFile = new File(new File(getWorkingDir()), zipName);
        if (isUrl && !zipFile.exists()) {
            if (spamOnce) {
                Main.log("Local file %s not found; downloading from %s",
                        zipFile.getAbsolutePath(),
                        zipUrl);
            }
            return 0 == Jsyringe.download_file_from_zip(zipUrl, zipPath, downloadPath);
        }
        while (!zipFile.exists()) {
            Main.log(Main.MessageStyle.Important, "Please put %s in the %s directory (URL not public)", zipName, getWorkingDir());
            try {
                Thread.sleep(5 * 1000);
            } catch (InterruptedException e) {
            }
        }
        if (spamOnce) {
            Main.log("Using local file %s", zipName);
        }
        try (ZipFile zf = new ZipFile(zipFile)){
            ZipEntry ze = zf.getEntry(zipPath);

            InputStream is = zf.getInputStream(ze);
			is.close();
        } catch (IOException e) {
            Main.error("IOException unpacking %s, check IPSW", zipPath);
            Main.exc(e);
            return false;
        }

        return true;
    }

    String downloadAndProcessFile(String zipPath) {
        Main.trace("Downloading %s", zipPath);
        String finalPath = new File(new File(ipswDir()), zipPath).getPath();
        // Ensure directory exists
        File finalFile = new File(finalPath);
        if (finalFile.exists()) {
            Main.trace("Skipping processing of %s, file already exists!", finalPath);
            return finalPath;
        }
        finalFile.getParentFile().mkdirs();
        Hashtable<String, String> fileProps = filePropsByName(zipPath);
        boolean needsDecrypting = !fileProps.containsKey("passthrough");

        String downloadPath = finalPath;
        if (needsDecrypting)
            downloadPath = finalPath + ".orig";
        if (new File(downloadPath).exists()) {
            Main.trace("Skipping download of %s, file already exists!", finalPath);
        } else {
            if (!getFileFromZip(ipswUrl, zipPath, downloadPath)) {
                Main.error("Download failed! %1$s [%2$s] -> %3$s", ipswUrl, zipPath, downloadPath);
                return null;
            }
            Main.trace("Downloaded to %s", downloadPath);
        }

        if (needsDecrypting) {
            String decryptedPath = finalPath + ".dec";
            if (!Jsyringe.process_img3_file(downloadPath, decryptedPath, null,
                    stringFromNsDict(dict, fileProps.get("iv")),
                    stringFromNsDict(dict, fileProps.get("key")))) {
                Main.error("Decryption failed");
                return null;
            }
            Main.trace("Decrypted to %s", decryptedPath);
            String patch = fileProps.get("patch");
            if (patch != null) {
                String patchedPath = decryptedPath + ".p";
                String patchJson = Background.getResourceFile(patch);
                if (patchJson == null) {
                    Main.error("getResourceFile(%s) failed, log a bug!", patch);
                    return null;
                }
                if (!Jsyringe.fuzzy_patch(decryptedPath, patchedPath, patchJson, 80)) {
                    Main.error("Patching failed");
                    return null;
                }
                decryptedPath = patchedPath;
                Main.trace("Patched to %s", patchedPath);
            }
            if (fileProps.containsKey("ramdisk")) {
                String sshTarFile = Background.getResourceFile("ssh.tar");
                if (sshTarFile == null) {
                    Main.error("getResourceFile(ssh.tar) failed, log a bug!");
                    return null;
                }
                long extend;
                long tarLength = new File(sshTarFile).length();
                if (tarLength == 0) {
                    Main.error("Can't get tar file size!");
                    return null;
                }
                extend = (long) (1.05 * (double) (tarLength));
                if (!Jsyringe.add_ssh_to_ramdisk(decryptedPath, sshTarFile, extend)) {
                    Main.error("Adding ssh to ramdisk failed!");
                    return null;
                }
                Main.trace("Added ssh.tar to the ramdisk");
            }
            if (!Jsyringe.process_img3_file(decryptedPath, finalPath, downloadPath,
                    stringFromNsDict(dict, fileProps.get("iv")),
                    stringFromNsDict(dict, fileProps.get("key")))) {
                Main.error("Encryption failed");
                return null;
            }
        }
        return finalPath;
    }

    boolean fetchKeysFromWiki() {
        NSDictionary plDict = new NSDictionary();
        int cSkipped = 0;
        for (DeviceProps dp : Device.supportedDevices) {
            if (dp.isDfuStub)
                continue;
            ArrayList<String> urls = WebScraper.getFirmwareUrls(dp.apName);
            boolean ok = false;
            Hashtable<String, String> dict = null;
            for (int fwPageIndex = urls.size() - 1; fwPageIndex >= 0; --fwPageIndex) {
                String url = urls.get(fwPageIndex);
                Main.trace("wiki URL: %s", url);
                dict = WebScraper.loadAndParseFirmwarePage(url);
                if (dict == null)
                    continue;
                for (Iterator<String> it = WebScraper.displayFields.iterator(); it.hasNext(); ) {
                    String key = it.next();
                    String value = dict.get(key);
                    if (value != null) {
                        Main.trace("%s\t: %s", key, value);
                    }
                }
                Main.trace("Enough keys: %s", WebScraper.hasEnoughKeys(dict) ? "YES" : "NO");

                if (WebScraper.hasEnoughKeys(dict)) {
                    ok = true;
                    break;
                }
            }
            if (ok && dict != null) {
                NSDictionary nsDict = new NSDictionary();
                Iterator<String> it = dict.keySet().iterator();
                while (it.hasNext()) {
                    String key = it.next();
                    String val = dict.get(key);
                    nsDict.put(key, val);
                }
                plDict.put(dp.apName, nsDict);
                Main.trace("Added %s!", dp.apName);
            } else {
                ++cSkipped;
                Main.trace("Skipped %s!", dp.apName);
            }
        }
        if (cSkipped != 0)
            return false;
        try {
            PropertyListParser.saveAsXML(plDict, new File("/tmp/all_keys.plist"));
            Main.success("Saved everything to file!");
            return true;
        } catch (IOException e1) {
            Main.error("Fetching keys from TheIphoneWiki failed!");
            Main.exc(e1);
        }
        return false;
    }

    void runTests() {
        ArrayList<DeviceProps> dps = Device.__TEST__getSupportedDevices();
        int cErrors = 0;
        for (DeviceProps dp : dps) {
            int pType = dp.productCode;
            if ((dp.productCode & 0xffff) != dp.productChip) {
                pType = 0x12220000 + dp.productCode;
            }
            _payloadCreationTest = true;
            _payloadCreatedOk = false;
            Device dev = new Device(0x1222, pType);
            onDfuDeviceArrival(dev);
            if (!_payloadCreatedOk) {
                Main.error("Error testing %s", dev.getName());
                ++cErrors;
            } else {
                Main.success("Device %s passed!", dev.getName());
            }
        }
        if (cErrors != 0) {
            Main.error("There were %d errors!", cErrors);
        } else
            Main.success("All devices passed!");
    }

    public void run() {
        try {
            if (Main.getTestOption()) {
                runTests();
            } else if (Main.getFetchOption()) {
                fetchKeysFromWiki();
            } else {
                while (true) {
                    Device d = staticDeviceQueue.poll(1, TimeUnit.SECONDS);
                    if (d != null)
                        onDfuDeviceArrival(d);
                }
            }
        } catch (Exception e) {
            Main.error("!! FAIL: Unhandled exception in background thread: %s, %s", e.toString(), e.getMessage());
            Main.exc(e);
        }
    }

    void onDfuDeviceArrival(Device dev) {
        Main.trace("DFU device '%s' connected", dev.getName());
        if (dev.isUnsupported()) {
            Main.error("Ignoring unsupported device %s", dev.getName());
            return;
        }
        if (this.device != null && this.device.getName().equals(dev.getName())) {
            Main.trace("Ignoring same device %s", dev.getName());
            return;
        }
        this.device = dev;
        prepareRamdiskForDevice();
    }

    void prepareRamdiskForDevice() {
        Main.log(Main.MessageStyle.Important, "Building ramdisk for device '%s'", device.getName());
        _ipswDir = null;
        String keyFileName = Background.getResourceFile("all_keys.plist");
        NSDictionary plDict;
        try {
            plDict = (NSDictionary) PropertyListParser.parse(new File(keyFileName));
        } catch (Exception e1) {
            Main.error("Cannot load all_keys.plist from resources; bailing !");
            Main.exc(e1);
            return;
        }
        dict = (NSDictionary) plDict.objectForKey(device.getAp());

        Main.trace("Working dir set to %s", getWorkingDir());

        ipswUrl = stringFromNsDict(dict, WebScraper.downloadUrl);

        Main.trace("IPSW at %s", ipswUrl);

        if (device.isWtfStub()) {
            dict.put(WebScraper.device, "dfu8900");
        }

        String restorePlistFile = downloadAndProcessFile("Restore.plist");
        if (restorePlistFile == null) {
            Main.error("Restore.plist download failed!");
            return;
        }
        Main.trace("Restore.plist downloaded to %s", restorePlistFile);

        Main.trace("Parsing Restore.plist..");

        File restorePlist = new File(restorePlistFile);

        NSDictionary restoreDict = null;
        try {
            restoreDict = (NSDictionary) PropertyListParser.parse(restorePlist);
        } catch (Exception e) {
            Main.error("Can't parse Restore.plist, bailing!");
            e.printStackTrace();
            return;
        }

        String iosVersion = stringFromNsDict(restoreDict, "ProductVersion");
        String[] verComponents = iosVersion.split("\\.");
        String iosVerMajor = verComponents[0];
        dict.put("ios", iosVerMajor);
        dict.put("ios" + iosVerMajor, "yes"); //ios5, ios4, ios3
        String iosVerMinor = "0";
        if (verComponents.length > 1) {
            iosVerMinor = verComponents[1];
        }
        dict.put("ios" + iosVerMajor + iosVerMinor, "yes");

        NSDictionary kcByTargetDict = (NSDictionary) restoreDict.objectForKey("KernelCachesByTarget");
        NSDictionary kcDict = null;
        if (kcByTargetDict != null) {
            String modelNoAp = device.getAp().replaceAll("ap$", "");
            kcDict = (NSDictionary) kcByTargetDict.objectForKey(modelNoAp);
        } else {
            kcDict = (NSDictionary) restoreDict.objectForKey("RestoreKernelCaches");
        }
        String kernelName = stringFromNsDict(kcDict, "Release");
        Main.trace("Kernel file: %s", kernelName);

        NSDictionary ramdisksDict = (NSDictionary) restoreDict.objectForKey("RestoreRamDisks");
        String ramdiskName = stringFromNsDict(ramdisksDict, "User");
        Main.trace("Restore ramdisk file: %s", ramdiskName);

        String dfuFolder = "Firmware/dfu/";
        String ibssName = String.format("iBSS.%s.RELEASE.dfu", device.getAp());
        String ibssPath = dfuFolder.concat(ibssName);

        if (!device.isWtfStub()) {
            String ibssFile = downloadAndProcessFile(ibssPath);

            if (ibssFile == null) {
                Main.error("iBSS download failed!");
                return;
            }
            Main.trace("iBSS prepared at %s", ibssFile);
        }

        String ibecFile = null;
        if (null != dict.objectForKey("ios5")) {
            String ibecName = String.format("iBEC.%s.RELEASE.dfu", device.getAp());
            String ibecPath = dfuFolder.concat(ibecName);

            ibecFile = downloadAndProcessFile(ibecPath);

            if (ibecFile == null) {
                Main.error("iBEC download failed!");
                return;
            }
            Main.trace("iBEC prepared at %s", ibecFile);
        }

        String wtf8900File = null;
        String wtfModelFile = null;
        if (device.isWtf() || device.isWtfStub()) {
            String wtf8900Name = "WTF.s5l8900xall.RELEASE.dfu";
            String wtf8900Path = dfuFolder.concat(wtf8900Name);
            String wtfModelName = String.format("WTF.%s.RELEASE.dfu", device.getAp());
            ;
            String wtfModelPath = dfuFolder.concat(wtfModelName);

            wtf8900File = downloadAndProcessFile(wtf8900Path);

            if (wtf8900File == null) {
                Main.error("WTF.s5l8900xall download failed!");
                return;
            }
            Main.trace("WTF.s5l8900xall prepared at %s", wtf8900File);

            if (!device.isWtfStub()) {
                wtfModelFile = downloadAndProcessFile(wtfModelPath);

                if (wtfModelFile == null) {
                    Main.error("%s download failed!", wtfModelName);
                    return;
                }

                Main.trace("%s prepared at %2s", wtfModelName, wtfModelFile);
            }
        }

        if (!device.isWtfStub()) {
            String deviceTreeName = String.format("DeviceTree.%s.img3", device.getAp());

            String deviceTreePath = String.format("Firmware/all_flash/all_flash.%s.production/%s", device.getAp(), deviceTreeName);

            String deviceTreeFile = downloadAndProcessFile(deviceTreePath);

            if (deviceTreeFile == null) {
                Main.error("Device tree download failed!");
                return;
            }
            Main.trace("Device tree prepared at %s", deviceTreeFile);


            String manifestPath = String.format("Firmware/all_flash/all_flash.%s.production/manifest", device.getAp());

            String manifestFile = downloadAndProcessFile(manifestPath);

            if (manifestFile == null) {
                Main.error("Manifest download failed!");
                return;
            }

            String kernelFile = downloadAndProcessFile(kernelName);

            if (kernelFile == null) {
                Main.trace("Kernel download failed!");
                return;
            }

            Main.trace("Kernel prepared at %s", kernelFile);

            String ramdiskFile = downloadAndProcessFile(ramdiskName);

            if (ramdiskFile == null) {
                Main.error("Ramdisk download failed!");
                return;
            }
            Main.trace("Ramdisk prepared at %s", ramdiskFile);

            if (_payloadCreationTest) {
                _payloadCreatedOk = true;
                return;
            }

            if (!device.isWtf()) {
                Main.log("Using syringe to exploit the bootrom..");
                if (0 != Jsyringe.exploit()) {
                    Main.error("Exploiting the device failed!");
                    return;
                }
                Main.success("Exploit sent!");
            }
        } // endif (!device.isWtfStub())
        if (_payloadCreationTest) {
            _payloadCreatedOk = true;
            return;
        }

        if (!device.isWtfStub()) {
            Main.log("Preparing to load the ramdisk..");
            _ramdiskSent = true;
        } else
            Main.log("Trying to pwn 8900 DFU mode..");

        if (!Jsyringe.restore_bundle(ipswDir())) {
            if (!device.isWtfStub())
                Main.error("Failed to use iTunes API to load the ramdisk!");
            else
                Main.error("Failed to use iTunes API to load the 8900 exploit!");
            return;
        }
        if (!device.isWtfStub())
            Main.log("Ramdisk load started!");
        else
            Main.log("8900 exploit load started!");
    }
}
