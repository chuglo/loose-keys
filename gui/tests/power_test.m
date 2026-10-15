// Process-local signals only: never asks macOS to sleep or change power mode.
#import "../src/notifications.m"
#include <assert.h>
#include <stdio.h>

static unsigned int sleepCount;
static bool asleep;
static unsigned int permissionCount;
static void sleepResult(bool value) { asleep = value; sleepCount++; }
static void permissionResult(unsigned char value) {
    assert(value == 4);
    permissionCount++;
}

int main(void) {
    @autoreleasepool {
        // The wake callback stops before notification APIs without a bundle.
        assert(NSBundle.mainBundle.bundleIdentifier == nil);
        permissionCallback = permissionResult;
        ch_background_init(sleepResult, NULL, NULL);
        NSNotificationCenter *center = NSWorkspace.sharedWorkspace.notificationCenter;
        for (unsigned int cycle = 0; cycle < 3; cycle++) {
            [center postNotificationName:NSWorkspaceWillSleepNotification object:nil];
            assert(asleep && sleepCount == cycle * 2 + 1);
            assert(permissionCount == cycle);
            [center postNotificationName:NSWorkspaceDidWakeNotification object:nil];
            assert(!asleep && sleepCount == cycle * 2 + 2);
            assert(permissionCount == cycle + 1);
        }
        [center removeObserver:sleepObserver];
        [center removeObserver:wakeObserver];
        if (@available(macOS 12.0, *)) {
            assert(ch_low_power() == NSProcessInfo.processInfo.lowPowerModeEnabled);
        } else {
            assert(!ch_low_power());
        }
        puts("Power bridge passed: local sleep/wake callbacks and read-only power query. No system power changes.");
    }
    return 0;
}
