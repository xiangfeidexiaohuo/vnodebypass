#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

const char *vnodeMemPath;
NSArray *hidePathList;

void saveVnode();
void hideVnode();
void revertVnode();
void recoveryVnode();
void checkFile();
int rerunAsRoot(void);