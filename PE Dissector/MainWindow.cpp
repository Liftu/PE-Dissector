#include "MainWindow.h"

MainWindow::MainWindow(QWidget *parent)
	: QMainWindow(parent)
{
	ui.setupUi(this);

	ui.treeWidget->setColumnCount(0);
	statusBarLabel = new QLabel(QString("No file loaded"), ui.statusBar);
	ui.statusBar->addWidget(statusBarLabel);

}
