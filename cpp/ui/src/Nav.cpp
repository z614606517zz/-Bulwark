#include "Nav.h"

#include <QCoreApplication>

NavHub* NavHub::instance()
{
    // Parented to the application: lives exactly as long as the UI does.
    static NavHub* hub = new NavHub(QCoreApplication::instance());
    return hub;
}
