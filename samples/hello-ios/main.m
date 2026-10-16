//
//  Hola iOS - primera app de NixerCode compilada en Windows.
//
//  Sin Mac, sin Xcode: clang + el SDK de iOS extraido del .xip de Apple.
//

#import <UIKit/UIKit.h>

@interface AppDelegate : UIResponder <UIApplicationDelegate>

@property (nonatomic, strong) UIWindow *window;

@end

@implementation AppDelegate

- (BOOL)application:(UIApplication *)application
        didFinishLaunchingWithOptions:(NSDictionary *)launchOptions
{
    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];

    UIViewController *controller = [[UIViewController alloc] init];
    controller.view.backgroundColor = [UIColor systemBackgroundColor];

    UILabel *title = [[UILabel alloc] initWithFrame:CGRectZero];
    title.text = @"Hola desde Windows";
    title.textAlignment = NSTextAlignmentCenter;
    title.font = [UIFont boldSystemFontOfSize:34.0];
    title.translatesAutoresizingMaskIntoConstraints = NO;

    UILabel *subtitle = [[UILabel alloc] initWithFrame:CGRectZero];
    subtitle.text = @"Compilado sin Mac, sin Xcode";
    subtitle.textAlignment = NSTextAlignmentCenter;
    subtitle.textColor = [UIColor secondaryLabelColor];
    subtitle.font = [UIFont systemFontOfSize:17.0];
    subtitle.translatesAutoresizingMaskIntoConstraints = NO;

    [controller.view addSubview:title];
    [controller.view addSubview:subtitle];

    [NSLayoutConstraint activateConstraints:@[
        [title.centerXAnchor constraintEqualToAnchor:controller.view.centerXAnchor],
        [title.centerYAnchor constraintEqualToAnchor:controller.view.centerYAnchor constant:-16.0],
        [subtitle.centerXAnchor constraintEqualToAnchor:controller.view.centerXAnchor],
        [subtitle.topAnchor constraintEqualToAnchor:title.bottomAnchor constant:8.0],
    ]];

    self.window.rootViewController = controller;
    [self.window makeKeyAndVisible];

    return YES;
}

@end

int main(int argc, char *argv[])
{
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
