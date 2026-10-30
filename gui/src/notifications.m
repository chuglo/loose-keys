#import <AppKit/AppKit.h>
#import <UserNotifications/UserNotifications.h>
#import <ServiceManagement/ServiceManagement.h>
#import <CommonCrypto/CommonHMAC.h>
#import <CoreServices/CoreServices.h>
#import <sys/stat.h>

// The launchd job in Contents/Library/LaunchAgents that runs the agent.
static NSString *const agentPlist = @"dev.loosekeys.agent.plist";

typedef void (*ReviewCallback)(void);
static ReviewCallback reviewCallback;
static id notificationDelegate;
static void (*permissionCallback)(unsigned char);
static void (*deliveryCallback)(unsigned long long, bool);
static bool (*deliveryAllowed)(unsigned long long);
static void (*sleepCallback)(bool);
static id sleepObserver;
static id wakeObserver;

static BOOL reviewIsVisible(void) {
    // The agent has no window. It asks whether the app is the one in front.
    // Not of NSWorkspace's frontmostApplication: in a process with no
    // application object that is not kept up to date. On macOS 14 it went on
    // naming this app after the app had quit, and the agent sent nothing
    // more. A list of the app's processes, asked for now, says which is
    // active now. The agent is not in it: it is no application to macOS.
    if (NSApp == nil) {
        NSString *bundle = NSBundle.mainBundle.bundleIdentifier;
        if (!bundle) return NO;
        for (NSRunningApplication *app in [NSRunningApplication runningApplicationsWithBundleIdentifier:bundle]) {
            if (app.isActive) return YES;
        }
        return NO;
    }
    if (!NSApp.isActive) return NO;
    for (NSWindow *window in NSApp.windows) {
        if (window.isVisible && !window.isMiniaturized && (window.styleMask & NSWindowStyleMaskTitled)) return YES;
    }
    return NO;
}

static bool login_event(NSAppleEventDescriptor *event) {
    return event != nil && event.eventClass == kCoreEventClass && event.eventID == kAEOpenApplication &&
        [event paramDescriptorForKeyword:keyAEPropData].enumCodeValue == keyAELaunchedAsLogInItem;
}

bool ch_launched_at_login(void) {
    return login_event(NSAppleEventManager.sharedAppleEventManager.currentAppleEvent);
}

static BOOL shouldOpenReview(NSString *identifier, NSString *action) {
    return [identifier isEqualToString:@"credential-review"] &&
        ([action isEqualToString:@"review"] || [action isEqualToString:UNNotificationDefaultActionIdentifier]);
}

static UNNotificationRequest *reviewRequest(void) {
    UNMutableNotificationContent *content = [UNMutableNotificationContent new];
    content.title = @"Loose Keys";
    content.body = NSLocalizedString(@"Found what looks like a password or key in a file. Open Loose Keys to see what to do.",
        @"Notification body, sent by the background helper when it finds something new to review.");
    content.categoryIdentifier = @"credential-review";
    // No userInfo, paths, accounts, counts, secrets, attachments, or sound.
    return [UNNotificationRequest requestWithIdentifier:@"credential-review" content:content trigger:nil];
}

// What the window is told: 3 allowed, 2 blocked, 1 not asked yet, and 5 when
// a request failed and macOS still records no answer. macOS answers a person
// who declines with an error, so an error alone does not mean it could not ask.
static unsigned char permissionValue(UNAuthorizationStatus status, BOOL requestFailed) {
    if (status == UNAuthorizationStatusAuthorized) return 3;
    if (status == UNAuthorizationStatusDenied) return 2;
    return requestFailed ? 5 : 1;
}

static void readPermission(BOOL requestFailed) {
    if (!NSBundle.mainBundle.bundleIdentifier) {
        if (permissionCallback) permissionCallback(4);
        return;
    }
    [UNUserNotificationCenter.currentNotificationCenter getNotificationSettingsWithCompletionHandler:^(UNNotificationSettings *settings) {
        if (permissionCallback) permissionCallback(permissionValue(settings.authorizationStatus, requestFailed));
    }];
}

static void updatePermission(void) { readPermission(NO); }

@interface ReviewNotifications : NSObject <UNUserNotificationCenterDelegate>
@end
@implementation ReviewNotifications
- (void)userNotificationCenter:(UNUserNotificationCenter *)center
 didReceiveNotificationResponse:(UNNotificationResponse *)response
         withCompletionHandler:(void (^)(void))completion {
    if (shouldOpenReview(response.notification.request.identifier, response.actionIdentifier)) {
        dispatch_async(dispatch_get_main_queue(), ^{ if (reviewCallback) reviewCallback(); });
    }
    completion();
}
- (void)userNotificationCenter:(UNUserNotificationCenter *)center
      willPresentNotification:(UNNotification *)notification
        withCompletionHandler:(void (^)(UNNotificationPresentationOptions))completion {
    // Recheck activity if the user switches apps while delivery is in progress.
    dispatch_async(dispatch_get_main_queue(), ^{
        completion(reviewIsVisible() ? UNNotificationPresentationOptionNone : UNNotificationPresentationOptionAlert);
    });
}
@end

void ch_notifications_init(ReviewCallback callback, void (*permission)(unsigned char)) {
    reviewCallback = callback;
    permissionCallback = permission;
    updatePermission();
    // UserNotifications requires an app bundle. Command-line builds remain usable.
    if (!NSBundle.mainBundle.bundleIdentifier) return;
    UNUserNotificationCenter *center = UNUserNotificationCenter.currentNotificationCenter;
    notificationDelegate = [ReviewNotifications new];
    center.delegate = notificationDelegate;
    UNNotificationAction *action = [UNNotificationAction actionWithIdentifier:@"review"
        title:NSLocalizedString(@"Review", @"Notification button that opens the app's review list.")
        options:UNNotificationActionOptionForeground];
    UNNotificationCategory *category = [UNNotificationCategory categoryWithIdentifier:@"credential-review"
        actions:@[action] intentIdentifiers:@[] options:UNNotificationCategoryOptionNone];
    [center setNotificationCategories:[NSSet setWithObject:category]];
}

void ch_notifications_permission(void) {
    if (!NSBundle.mainBundle.bundleIdentifier) {
        if (permissionCallback) permissionCallback(4);
        return;
    }
    [UNUserNotificationCenter.currentNotificationCenter requestAuthorizationWithOptions:UNAuthorizationOptionAlert
        completionHandler:^(BOOL granted, NSError *error) {
            readPermission(error != nil);
        }];
}

// Ask macOS again whether notifications are allowed. The answer comes back
// through the permission callback.
void ch_notifications_refresh(void) { updatePermission(); }

void ch_notifications_send(unsigned long long revision) {
    if (!NSBundle.mainBundle.bundleIdentifier) { if (deliveryCallback) deliveryCallback(revision, false); return; }
    UNUserNotificationCenter *center = UNUserNotificationCenter.currentNotificationCenter;
    [center getNotificationSettingsWithCompletionHandler:^(UNNotificationSettings *settings) {
        if (settings.authorizationStatus != UNAuthorizationStatusAuthorized) { if (deliveryCallback) deliveryCallback(revision, false); return; }
        dispatch_async(dispatch_get_main_queue(), ^{
            if (deliveryAllowed && !deliveryAllowed(revision)) { if (deliveryCallback) deliveryCallback(revision, false); return; }
            if (reviewIsVisible()) { if (deliveryCallback) deliveryCallback(revision, false); return; }
            [center addNotificationRequest:reviewRequest() withCompletionHandler:^(NSError *error) {
                if (deliveryCallback) deliveryCallback(revision, error == nil);
            }];
        });
    }];
}

bool ch_app_active(void) { return reviewIsVisible(); }

void ch_background_init(void (*sleep)(bool), void (*delivery)(unsigned long long, bool), bool (*allowed)(unsigned long long)) {
    sleepCallback = sleep;
    deliveryCallback = delivery;
    deliveryAllowed = allowed;
    NSNotificationCenter *center = NSWorkspace.sharedWorkspace.notificationCenter;
    sleepObserver = [center addObserverForName:NSWorkspaceWillSleepNotification object:nil queue:nil usingBlock:^(NSNotification *note) {
        if (sleepCallback) sleepCallback(true);
    }];
    wakeObserver = [center addObserverForName:NSWorkspaceDidWakeNotification object:nil queue:nil usingBlock:^(NSNotification *note) {
        updatePermission();
        if (sleepCallback) sleepCallback(false);
    }];
}

// 0 unavailable, 1 disabled, 2 enabled, 3 approval required, 4 error/not found.
static unsigned char serviceStatus(SMAppService *service) API_AVAILABLE(macos(13.0)) {
    switch (service.status) {
        case SMAppServiceStatusNotRegistered: return 1;
        case SMAppServiceStatusEnabled: return 2;
        case SMAppServiceStatusRequiresApproval: return 3;
        default: return 4;
    }
}

static unsigned char serviceSet(SMAppService *service, bool enabled) API_AVAILABLE(macos(13.0)) {
    NSError *error = nil;
    BOOL ok;
    if (enabled) {
        ok = [service registerAndReturnError:&error];
    } else {
        // The synchronous unregister returns before the old service is
        // reaped. Wait for Apple's completion before allowing a subsequent
        // registration. Engine requests run off the main thread; Apple's
        // completion runs on the default dispatch queue.
        dispatch_semaphore_t finished = dispatch_semaphore_create(0);
        __block BOOL removed = NO;
        [service unregisterWithCompletionHandler:^(NSError *failure) {
            removed = failure == nil;
            dispatch_semaphore_signal(finished);
        }];
        // A missing completion must not hang the request or permit a new
        // registration. The block retains its state if it completes late.
        if (dispatch_semaphore_wait(finished, dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC)) != 0) return 4;
        ok = removed;
    }
    return ok ? serviceStatus(service) : 4;
}

// The background agent's launchd job.
unsigned char ch_login_status(void) {
    if (@available(macOS 13.0, *)) return serviceStatus([SMAppService agentServiceWithPlistName:agentPlist]);
    return 0;
}

unsigned char ch_login_set(bool enabled) {
    if (@available(macOS 13.0, *)) return serviceSet([SMAppService agentServiceWithPlistName:agentPlist], enabled);
    return 0;
}

// The app itself in Login Items, which opens it at login in the menu bar.
// Same codes as the agent's job.
unsigned char ch_app_login_status(void) {
    if (@available(macOS 13.0, *)) return serviceStatus([SMAppService mainAppService]);
    return 0;
}

unsigned char ch_app_login_set(bool enabled) {
    if (@available(macOS 13.0, *)) return serviceSet([SMAppService mainAppService], enabled);
    return 0;
}

void ch_fingerprint(const unsigned char *key, const unsigned char *bytes, size_t length, bool shared, unsigned char *out) {
    CCHmacContext context;
    CCHmacInit(&context, kCCHmacAlgSHA256, key, 32);
    CCHmacUpdate(&context, &shared, sizeof(shared));
    CCHmacUpdate(&context, bytes, length);
    CCHmacFinal(&context, out);
}

// ---- Background agent ----

static FSEventStreamRef watchStream;
static void (*watchChange)(const char *, unsigned int);
static void (*watchBatch)(unsigned long long);

static void watchCallback(ConstFSEventStreamRef stream, void *info, size_t count, void *paths,
                          const FSEventStreamEventFlags flags[], const FSEventStreamEventId ids[]) {
    char **list = paths;
    for (size_t i = 0; i < count; i++) watchChange(list[i], flags[i]);
    if (count) watchBatch(ids[count - 1]);
}

// Report file changes under one folder, batched every `latency` seconds on a
// background queue. `since` is the last event already handled, or 0 for now.
bool ch_watch_start(const char *path, unsigned long long since, double latency,
                    void (*change)(const char *, unsigned int), void (*batch)(unsigned long long)) {
    watchChange = change;
    watchBatch = batch;
    CFStringRef folder = CFStringCreateWithFileSystemRepresentation(NULL, path);
    if (!folder) return false;
    CFArrayRef folders = CFArrayCreate(NULL, (const void **)&folder, 1, &kCFTypeArrayCallBacks);
    // Our own writes to the state file are not reported back to us.
    watchStream = FSEventStreamCreate(NULL, watchCallback, NULL, folders,
        since ? since : kFSEventStreamEventIdSinceNow, latency,
        kFSEventStreamCreateFlagFileEvents | kFSEventStreamCreateFlagIgnoreSelf);
    CFRelease(folders);
    CFRelease(folder);
    if (!watchStream) return false;
    dispatch_queue_attr_t quiet = dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL, QOS_CLASS_BACKGROUND, 0);
    FSEventStreamSetDispatchQueue(watchStream, dispatch_queue_create("dev.loosekeys.watch", quiet));
    return FSEventStreamStart(watchStream);
}

// Identifies the change history of the volume holding `path`. Event numbers
// are only meaningful while this stays the same. `out` holds 37 bytes.
bool ch_watch_volume(const char *path, char *out) {
    struct stat info;
    if (stat(path, &info) != 0) return false;
    CFUUIDRef uuid = FSEventsCopyUUIDForDevice(info.st_dev);
    if (!uuid) return false;
    CFStringRef text = CFUUIDCreateString(NULL, uuid);
    bool ok = CFStringGetCString(text, out, 37, kCFStringEncodingASCII);
    CFRelease(text);
    CFRelease(uuid);
    return ok;
}

bool ch_low_power(void) {
    if (@available(macOS 12.0, *)) return NSProcessInfo.processInfo.lowPowerModeEnabled;
    return false;
}

// Show the app's review page: bring a running app forward, or start it.
// macOS starts the app itself for a click on its notification, and hands
// that app the click, at the same moment as it tells the agent. Started from
// here at once, there were two apps (seen on macOS 14). So this waits a
// moment and starts one only if none has appeared.
void ch_open_app(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        NSWorkspaceOpenConfiguration *configuration = [NSWorkspaceOpenConfiguration configuration];
        configuration.arguments = @[@"--review"];
        pid_t me = NSProcessInfo.processInfo.processIdentifier;
        BOOL running = NO;
        for (NSRunningApplication *app in [NSRunningApplication runningApplicationsWithBundleIdentifier:NSBundle.mainBundle.bundleIdentifier]) {
            if (app.processIdentifier != me) running = YES;
        }
        // The agent runs from the same bundle, so ask for a separate app process.
        configuration.createsNewApplicationInstance = !running;
        [NSWorkspace.sharedWorkspace openApplicationAtURL:NSBundle.mainBundle.bundleURL
                                            configuration:configuration completionHandler:nil];
    });
}

// Serve notifications and sleep/wake callbacks for a process with no window.
void ch_agent_run(void) {
    [NSTimer scheduledTimerWithTimeInterval:1e9 repeats:YES block:^(NSTimer *timer) {}];
    CFRunLoopRun();
}
