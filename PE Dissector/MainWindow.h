#pragma once

#include <Windows.h>
// As the PE Dissector API is written in C, we have to specify it to the compiler
extern "C" {
	typedef struct _PE_HEADERS32 PE_HEADERS32, *PPE_HEADERS32;
	typedef unsigned __int64 QWORD;
	BOOL isFileExecutable(HANDLE hFile);
	WORD getArchitecture(HANDLE hFile);
	BOOL readPEHeaders32(HANDLE hFile, PPE_HEADERS32 peHeaders32);
	WORD getSectionOfRVA(QWORD RVA, WORD numberOfSections, PIMAGE_SECTION_HEADER sectionHeaders);
};
#include "PE Dissector.h"
#include "QTabContent.h"

#include <QtWidgets/QMainWindow>
#include <QtWidgets/qlabel.h>
#include <QtWidgets/qfiledialog.h>
#include <QtWidgets/qmessagebox.h>
#include <QtWidgets/qpushbutton.h>
#include <QtWidgets/qtablewidget.h>
#include <QtCore/qfile.h>
#include <QtCore/qdebug.h>

#include "ui_MainWindow.h"


class MainWindow : public QMainWindow
{
	Q_OBJECT

public:
	MainWindow(QWidget *parent = Q_NULLPTR);

public slots:
	void actionOpen_File_triggered();
	void actionClose_File_triggered();
	void actionOld_Windows_Theme_toggled(bool checked);
	void tabManager_currentChanged(int tabIndex);
	void treeView_selectionChanged();

private:
	bool addFile(QString filename);
	void updateTreeView(QTreeWidgetItem* treeRootItem);

	Ui::MainWindowClass ui;
	QLabel* statusBarLabel;
};
