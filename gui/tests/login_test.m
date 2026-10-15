// Exercise the native registration bridge without touching ServiceManagement.
#import <AppKit/AppKit.h>
#import <UserNotifications/UserNotifications.h>
#import <ServiceManagement/ServiceManagement.h>
#include <assert.h>

@interface FakeLoginService : NSObject
@property SMAppServiceStatus status;
@property(copy) void (^completion)(NSError *);
@property BOOL usedCompletion;
+ (instancetype)agentServiceWithPlistName:(NSString *)name;
- (BOOL)registerAndReturnError:(NSError **)error;
- (BOOL)unregisterAndReturnError:(NSError **)error;
- (void)unregisterWithCompletionHandler:(void (^)(NSError *))handler;
@end

static FakeLoginService *service;
static dispatch_semaphore_t invoked;
@implementation FakeLoginService
+ (instancetype)agentServiceWithPlistName:(NSString *)name { return service; }
- (BOOL)registerAndReturnError:(NSError **)error { self.status = SMAppServiceStatusEnabled; return YES; }
- (BOOL)unregisterAndReturnError:(NSError **)error {
    self.status = SMAppServiceStatusNotRegistered;
    dispatch_semaphore_signal(invoked);
    return YES; // Cleanup is still pending, despite synchronous success.
}
- (void)unregisterWithCompletionHandler:(void (^)(NSError *))handler {
    self.usedCompletion = YES;
    self.completion = handler;
    dispatch_semaphore_signal(invoked);
}
@end

#define SMAppService FakeLoginService
#import "../src/notifications.m"
#undef SMAppService

static void checkUnregister(BOOL fail) {
    service = [FakeLoginService new];
    service.status = SMAppServiceStatusEnabled;
    invoked = dispatch_semaphore_create(0);
    dispatch_semaphore_t returned = dispatch_semaphore_create(0);
    __block unsigned char result = 0;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
        result = ch_login_set(false);
        dispatch_semaphore_signal(returned);
    });
    assert(dispatch_semaphore_wait(invoked, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC)) == 0);
    assert(service.usedCompletion && "Unregister must wait for service cleanup, not synchronous acceptance");
    assert(dispatch_semaphore_wait(returned, DISPATCH_TIME_NOW) != 0);
    service.status = SMAppServiceStatusNotRegistered;
    service.completion(fail ? [NSError errorWithDomain:@"synthetic" code:1 userInfo:nil] : nil);
    assert(dispatch_semaphore_wait(returned, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC)) == 0);
    assert(result == (fail ? 4 : 1));
    service.completion = nil;
}

static void checkMissingCompletion(void) {
    service = [FakeLoginService new];
    service.status = SMAppServiceStatusEnabled;
    invoked = dispatch_semaphore_create(0);
    dispatch_semaphore_t returned = dispatch_semaphore_create(0);
    __block unsigned char result = 0;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
        result = ch_login_set(false);
        dispatch_semaphore_signal(returned);
    });
    assert(dispatch_semaphore_wait(invoked, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC)) == 0);
    assert(dispatch_semaphore_wait(returned, dispatch_time(DISPATCH_TIME_NOW, 12 * NSEC_PER_SEC)) == 0);
    assert(result == 4);
    // A late callback must remain safe after the bridge request has returned.
    service.completion(nil);
    service.completion = nil;
    assert(service.status == SMAppServiceStatusEnabled);
}

int main(void) {
    @autoreleasepool {
        checkUnregister(NO);
        checkUnregister(YES);
        assert(ch_login_set(true) == 2);
        checkMissingCompletion();
        puts("Login bridge waits for cleanup, propagates errors, and bounds missing completions. No services registered.");
    }
    return 0;
}
