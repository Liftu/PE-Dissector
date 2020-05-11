#include "MainWindow.h"

MainWindow::MainWindow(QWidget *parent)
	: QMainWindow(parent)
{
	ui.setupUi(this);

	statusBarLabel = new QLabel(QString("No file loaded"), ui.statusBar);
	ui.statusBar->addWidget(statusBarLabel);

	ui.treeView->setColumnCount(0);
}

void MainWindow::actionOpen_File_triggered()
{
	qDebug() << "open file";
	QStringList fileList = QFileDialog::getOpenFileNames(this, QString("Select a PE file to dissect"), QString(),
		QString("All files (*.*);;All PE files (*.exe *.dll *.sys *.drv *.ocx *.cpl *.scr);;Exe files (*.exe);;Dll files (*.dll);;System files (*.sys *.drv);;ActiveX control files (*.ocx);;Control panel files (*.cpl);;Screensaver files(*.scr)"),
		&QString("All PE files (*.exe *.dll *.sys *.drv *.ocx *.cpl *.scr)"));
	for (QString filename : fileList)
	{
		qDebug() << "file : " << filename;
		addFile(filename);
	}
}

void MainWindow::actionClose_File_triggered()
{
	qDebug() << "close file : " << ui.tabManager->currentIndex();

	disconnect(ui.actionToggle_List_View, SIGNAL(triggered(bool)), ui.tabManager->widget(ui.tabManager->currentIndex()), SLOT(actionToggle_List_View_triggered(bool)));
	disconnect(ui.actionToggle_Hex_View, SIGNAL(triggered(bool)), ui.tabManager->widget(ui.tabManager->currentIndex()), SLOT(actionToggle_Hex_View_triggered(bool)));

	// Remove the tree root item otherwise it won't if it's the last file.
	ui.treeView->takeTopLevelItem(0);
	ui.treeView->setColumnCount(0);
	// Delete the widget of a tab when removing a tab.
	QWidget* tabContent = ui.tabManager->widget(ui.tabManager->currentIndex());
	ui.tabManager->removeTab(ui.tabManager->currentIndex());
	delete tabContent;

	if (!ui.tabManager->count())
	{
		ui.actionClose_File->setEnabled(false);
		ui.actionSave_File->setEnabled(false);
		ui.actionSave_As->setEnabled(false);
		ui.actionSave_All->setEnabled(false);
		ui.actionToggle_List_View->setEnabled(false);
		ui.actionToggle_Hex_View->setEnabled(false);
	}
}

void MainWindow::tabManager_currentChanged(int tabIndex)
{
	qDebug() << "tab changed, current = " << tabIndex;
	if (tabIndex >= 0)
	{
		updateTreeView(((QTabContent*)ui.tabManager->widget(tabIndex))->getTreeRootItem());
	}
}

void MainWindow::treeView_selectionChanged()
{
	if (ui.treeView->currentItem())
	{
		qDebug() << "treeView selection changed : " << ui.treeView->currentItem()->text(0);
	}
}

bool MainWindow::addFile(QString filename)
{
	statusBarLabel->setText(QString("Loading file ") + QFileInfo(filename).fileName() + QString("..."));
	HANDLE hFile = CreateFileA(filename.toLocal8Bit().data(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		statusBarLabel->setText(QString("Failed to open ") + QFileInfo(filename).fileName() + QString("!"));
		return false;
	}

	if (!isFileExecutable(hFile))
	{
		statusBarLabel->setText(QFileInfo(filename).fileName() + QString(" is not a PE file"));
		return false;
	}

	if (getArchitecture(hFile) != IMAGE_FILE_MACHINE_I386)
	{
		QMessageBox::warning(this, QFileInfo(filename).fileName(), QString("PE Dissector only supports 32 bits application for now."));
		statusBarLabel->setText(QString("Architecture of ") + QFileInfo(filename).fileName() + QString(" not supported."));
		return false;
	}
	
	PPE_HEADERS32 peHeaders32 = new PE_HEADERS32;
	if (!readPEHeaders32(hFile, peHeaders32))
	{
		statusBarLabel->setText(QString("Error while parsing ") + QFileInfo(filename).fileName() + QString("!"));
		return false;
	}

	statusBarLabel->setText(QFileInfo(filename).fileName() + QString(" successfully loaded"));

	// Get the List View and Hex View and put them in a new tab.
	QTabContent* tabContent = new QTabContent(filename, peHeaders32, ui.actionToggle_List_View->isChecked(), ui.actionToggle_Hex_View->isChecked());
	connect(ui.actionToggle_List_View, SIGNAL(toggled(bool)), tabContent, SLOT(actionToggle_List_View_triggered(bool)));
	connect(ui.actionToggle_Hex_View, SIGNAL(toggled(bool)), tabContent, SLOT(actionToggle_Hex_View_triggered(bool)));
	ui.tabManager->setCurrentIndex(ui.tabManager->addTab(tabContent, QFileInfo(filename).fileName()));

	ui.actionClose_File->setEnabled(true);
	//ui.actionSave_File->setEnabled(true);
	//ui.actionSave_As->setEnabled(true);
	//ui.actionSave_All->setEnabled(true);
	ui.actionToggle_List_View->setEnabled(true);
	ui.actionToggle_Hex_View->setEnabled(true);

	CloseHandle(hFile);
	return true;
}

void MainWindow::updateTreeView(QTreeWidgetItem* treeRootItem)
{
	qDebug() << "treeView update";
	ui.treeView->setColumnCount(0);
	ui.treeView->setHeaderLabels(QStringList("Header"));
	ui.treeView->takeTopLevelItem(0);
	ui.treeView->addTopLevelItem(treeRootItem);
	ui.treeView->expandAll();
}

