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
+ (instancetype)mainAppService;
- (BOOL)registerAndReturnError:(NSError **)error;
- (BOOL)unregisterAndReturnError:(NSError **)error;
- (void)unregisterWithCompletionHandler:(void (^)(NSError *))handler;
@end

// The helper's job and the app itself are separate services, so a bridge
// that reaches the wrong one is seen.
static FakeLoginService *agent;
static FakeLoginService *mainApp;
static FakeLoginService *service;
static dispatch_semaphore_t invoked;
@implementation FakeLoginService
+ (instancetype)agentServiceWithPlistName:(NSString *)name { return agent; }
+ (instancetype)mainAppService { return mainApp; }
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

// Both services fresh and in `status`; `service` is the one `target` names.
static FakeLoginService *other;
static void fresh(FakeLoginService *__strong *target, SMAppServiceStatus status) {
    agent = [FakeLoginService new];
    mainApp = [FakeLoginService new];
    agent.status = mainApp.status = status;
    service = *target;
    other = service == agent ? mainApp : agent;
}

static void checkOtherUntouched(SMAppServiceStatus status) {
    assert(other.status == status && !other.usedCompletion && "a bridge changes only its own service");
}

static void checkUnregister(unsigned char (*set)(bool), FakeLoginService *__strong *target, BOOL fail) {
    fresh(target, SMAppServiceStatusEnabled);
    invoked = dispatch_semaphore_create(0);
    dispatch_semaphore_t returned = dispatch_semaphore_create(0);
    __block unsigned char result = 0;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
        result = set(false);
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
    checkOtherUntouched(SMAppServiceStatusEnabled);
}

static void checkMissingCompletion(unsigned char (*set)(bool), FakeLoginService *__strong *target) {
    fresh(target, SMAppServiceStatusEnabled);
    invoked = dispatch_semaphore_create(0);
    dispatch_semaphore_t returned = dispatch_semaphore_create(0);
    __block unsigned char result = 0;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
        result = set(false);
        dispatch_semaphore_signal(returned);
    });
    assert(dispatch_semaphore_wait(invoked, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC)) == 0);
    assert(dispatch_semaphore_wait(returned, dispatch_time(DISPATCH_TIME_NOW, 12 * NSEC_PER_SEC)) == 0);
    assert(result == 4);
    // A late callback must remain safe after the bridge request has returned.
    service.completion(nil);
    service.completion = nil;
    assert(service.status == SMAppServiceStatusEnabled);
    checkOtherUntouched(SMAppServiceStatusEnabled);
}

static void checkRegister(unsigned char (*set)(bool), unsigned char (*status)(void), FakeLoginService *__strong *target) {
    fresh(target, SMAppServiceStatusNotRegistered);
    assert(status() == 1);
    assert(set(true) == 2 && service.status == SMAppServiceStatusEnabled);
    checkOtherUntouched(SMAppServiceStatusNotRegistered);
    // Each status reads its own service.
    other.status = SMAppServiceStatusRequiresApproval;
    assert(status() == 2);
}

int main(void) {
    @autoreleasepool {
        // The helper's job, then the app itself.
        unsigned char (*setters[])(bool) = {ch_login_set, ch_app_login_set};
        unsigned char (*statuses[])(void) = {ch_login_status, ch_app_login_status};
        FakeLoginService *__strong *targets[] = {&agent, &mainApp};
        for (int i = 0; i < 2; i++) {
            checkUnregister(setters[i], targets[i], NO);
            checkUnregister(setters[i], targets[i], YES);
            checkRegister(setters[i], statuses[i], targets[i]);
            checkMissingCompletion(setters[i], targets[i]);
        }
        puts("Both login bridges wait for cleanup, propagate errors, and bound missing completions. No services registered.");
    }
    return 0;
}
