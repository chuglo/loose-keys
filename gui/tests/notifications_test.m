// Builds the bridge and checks payload/routing without sending a notification.
#import "../src/notifications.m"
#include <assert.h>
#include <stdio.h>

static unsigned char permissionStatus;
static void permissionResult(unsigned char value) { permissionStatus = value; }
static unsigned long long deliveredRevision;
static bool deliveredSuccess;
static void deliveryResult(unsigned long long revision, bool success) { deliveredRevision = revision; deliveredSuccess = success; }

int main(void) {
    @autoreleasepool {
        // Stop before any permission API if this test is placed inside a bundle.
        assert(NSBundle.mainBundle.bundleIdentifier == nil);
        permissionCallback = permissionResult;
        ch_notifications_permission();
        assert(permissionStatus == 4);
        // A request macOS answers with an error has still been answered: a
        // person who declines is told "blocked", not "could not ask".
        assert(permissionValue(UNAuthorizationStatusAuthorized, NO) == 3);
        assert(permissionValue(UNAuthorizationStatusAuthorized, YES) == 3);
        assert(permissionValue(UNAuthorizationStatusDenied, NO) == 2);
        assert(permissionValue(UNAuthorizationStatusDenied, YES) == 2);
        assert(permissionValue(UNAuthorizationStatusNotDetermined, NO) == 1);
        assert(permissionValue(UNAuthorizationStatusNotDetermined, YES) == 5);
        deliveryCallback = deliveryResult;
        ch_notifications_send(7);
        assert(deliveredRevision == 7 && !deliveredSuccess);
        UNNotificationRequest *request = reviewRequest();
        UNNotificationContent *content = request.content;
        assert([content.title isEqualToString:@"Loose Keys"]);
        assert([content.body isEqualToString:@"Potential local credential exposure found. Review safe next steps. This does not prove theft."]);
        assert([request.identifier isEqualToString:@"credential-review"]);
        assert([content.categoryIdentifier isEqualToString:@"credential-review"]);
        assert(content.userInfo.count == 0);
        assert(content.attachments.count == 0);
        assert(content.subtitle.length == 0);
        assert(content.threadIdentifier.length == 0);
        assert(content.targetContentIdentifier == nil);
        assert(content.badge == nil);
        assert(content.sound == nil);
        assert(request.trigger == nil);
        assert(shouldOpenReview(@"credential-review", @"review"));
        assert(shouldOpenReview(@"credential-review", UNNotificationDefaultActionIdentifier));
        assert(!shouldOpenReview(@"credential-review", UNNotificationDismissActionIdentifier));
        assert(!shouldOpenReview(@"other", @"review"));
        assert(!login_event(nil));
        NSAppleEventDescriptor *launch = [NSAppleEventDescriptor appleEventWithEventClass:kCoreEventClass eventID:kAEOpenApplication targetDescriptor:nil returnID:kAutoGenerateReturnID transactionID:kAnyTransactionID];
        assert(!login_event(launch));
        [launch setParamDescriptor:[NSAppleEventDescriptor descriptorWithEnumCode:keyAELaunchedAsLogInItem] forKeyword:keyAEPropData];
        assert(login_event(launch));
        [launch setParamDescriptor:[NSAppleEventDescriptor descriptorWithEnumCode:keyAELaunchedAsServiceItem] forKeyword:keyAEPropData];
        assert(!login_event(launch));
        NSAppleEventDescriptor *wrong = [NSAppleEventDescriptor appleEventWithEventClass:kCoreEventClass eventID:kAEReopenApplication targetDescriptor:nil returnID:kAutoGenerateReturnID transactionID:kAnyTransactionID];
        [wrong setParamDescriptor:[NSAppleEventDescriptor descriptorWithEnumCode:keyAELaunchedAsLogInItem] forKeyword:keyAEPropData];
        assert(!login_event(wrong));
        wrong = [NSAppleEventDescriptor appleEventWithEventClass:'test' eventID:kAEOpenApplication targetDescriptor:nil returnID:kAutoGenerateReturnID transactionID:kAnyTransactionID];
        [wrong setParamDescriptor:[NSAppleEventDescriptor descriptorWithEnumCode:keyAELaunchedAsLogInItem] forKeyword:keyAEPropData];
        assert(!login_event(wrong));
        unsigned char key[32] = {0}, digest[32], expected[32];
        const unsigned char synthetic[] = {0, 'f', 'i', 'x', 't', 'u', 'r', 'e'};
        ch_fingerprint(key, synthetic + 1, sizeof(synthetic) - 1, false, digest);
        CCHmac(kCCHmacAlgSHA256, key, sizeof(key), synthetic, sizeof(synthetic), expected);
        assert(memcmp(digest, expected, sizeof(digest)) == 0);
        unsigned char changed[32];
        ch_fingerprint(key, synthetic + 1, sizeof(synthetic) - 1, true, changed);
        assert(memcmp(digest, changed, sizeof(digest)) != 0);
        puts("Native unavailable permission/delivery, generic payload, login events, keyed digest, and click routing checks passed. No notifications sent.");
    }
    return 0;
}
