#include "MainWindow.h"

MainWindow::MainWindow(QWidget *parent)
	: QMainWindow(parent)
{
	ui.setupUi(this);

	statusBarLabel = new QLabel(QString("No file loaded"), ui.statusBar);
	ui.statusBar->addWidget(statusBarLabel);

	ui.headerTree->setColumnCount(0);
}

void MainWindow::headerTree_selectionChanged()
{
	qDebug() << "toto";
}

void MainWindow::actionOpen_File_triggered()
{
	qDebug() << "open file";
	QStringList fileList = QFileDialog::getOpenFileNames(this, QString("Select a PE file to dissect"), QString(), 
		QString("All files (*.*);;All PE files (*.exe *.dll *.sys *.drv *.ocx *.cpl *.scr);;Exe files (*.exe);;Dll files (*.dll);;System files (*.sys *.drv);;ActiveX control files (*.ocx);;Control panel files (*.cpl);;Screensaver files(*.scr)"),
		&QString("All PE files (*.exe *.dll *.sys *.drv *.ocx *.cpl *.scr)"));
	for (QString filename : fileList)
	{
		qDebug() << "file : ";
		qDebug() << filename;
		addFile(filename);
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
		QMessageBox::warning(this, QString("Architecture not supported"), QString("PE Dissector only supports 32 bits application for now."));
		statusBarLabel->setText(QString("Architecture of ") + QFileInfo(filename).fileName() + QString(" not supported."));
		return false;
	}
	
	PE_HEADERS32 peHeader32;
	if (!readPEHeaders32(hFile, &peHeader32))
	{
		statusBarLabel->setText(QString("Error while parsing ") + QFileInfo(filename).fileName() + QString("!"));
		return false;
	}

	statusBarLabel->setText(QFileInfo(filename).fileName() + QString(" successfully loaded"));

	CloseHandle(hFile);
	return true;
}
