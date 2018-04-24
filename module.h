#ifndef MODULE_H
#define MODULE_H

#include "Qt_common_api.h"
#include "mme_define.h"
#include <QThread>
#include <QMutex>

class CCModule : public QThread
{
public:
	CCModule();
	~CCModule();
	virtual void run();
};

#endif // MODULE_H