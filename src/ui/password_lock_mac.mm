#import <Cocoa/Cocoa.h>
#include "password_lock.h"

namespace ui {

bool showPasswordLock(const std::string& title, const std::string& message, const std::string& requiredPassword);

bool showPasswordLock(const std::string& title, const std::string& message, const std::string& requiredPassword) {
    @autoreleasepool {
        [NSApplication sharedApplication];
        NSRect screenRect = [[NSScreen mainScreen] frame];
        NSWindow* win = [[NSWindow alloc] initWithContentRect:screenRect
            styleMask:NSWindowStyleMaskBorderless
            backing:NSBackingStoreBuffered defer:NO];
        [win setLevel:NSScreenSaverWindowLevel];
        [win setOpaque:YES];
        [win setBackgroundColor:[NSColor blackColor]];
        [win setCollectionBehavior:NSWindowCollectionBehaviorCanJoinAllSpaces|NSWindowCollectionBehaviorFullScreenAuxiliary];
        [win makeKeyAndOrderFront:nil];

        NSTextField* label = [[NSTextField alloc] initWithFrame:NSMakeRect(NSMidX(screenRect)-200, NSMidY(screenRect)+20, 400, 24)];
        [label setBordered:NO]; [label setEditable:NO]; [label setDrawsBackground:NO];
        [label setAlignment:NSTextAlignmentCenter];
        [label setStringValue:[NSString stringWithUTF8String:message.c_str()]];

        NSSecureTextField* field = [[NSSecureTextField alloc] initWithFrame:NSMakeRect(NSMidX(screenRect)-200, NSMidY(screenRect)-20, 400, 32)];
        NSButton* btn = [[NSButton alloc] initWithFrame:NSMakeRect(NSMidX(screenRect)+210, NSMidY(screenRect)-20, 80, 32)];
        [btn setTitle:@"OK"]; [btn setButtonType:NSButtonTypeMomentaryPushIn]; [btn setBezelStyle:NSBezelStyleRounded];
        [[win contentView] addSubview:label];
        [[win contentView] addSubview:field];
        [[win contentView] addSubview:btn];

        __block bool success = false;
        [btn setAction:@selector(performClick:)];
        [btn setTarget:[NSBlockOperation blockOperationWithBlock:^{
            NSString* txt = [field stringValue];
            std::string utf8([txt UTF8String]);
            if (utf8 == requiredPassword) { success = true; [NSApp stop:nil]; }
            else { [field setStringValue:@""]; }
        }]];

        [NSApp run];
        [win orderOut:nil];
        return success;
    }
}

}


