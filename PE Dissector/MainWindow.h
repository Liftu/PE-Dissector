#pragma once

#include <Windows.h>
#include <QtWidgets/QMainWindow>
#include <QtWidgets/qlabel.h>
#include <QtWidgets/qfiledialog.h>
#include <QtWidgets/qmessagebox.h>
#include <QtCore/qfile.h>
#include <QtCore/qdebug.h>

#include "ui_MainWindow.h"

// As the PE Dissector API is written in C, we have to specify it to the compiler
extern "C" {
	typedef struct _PE_HEADERS32 PE_HEADERS32, *PPE_HEADERS32;
	typedef unsigned __int64 QWORD;
	BOOL isFileExecutable(HANDLE hFile);
	WORD getArchitecture(HANDLE hFile);
	BOOL readPEHeaders32(HANDLE hFile, PPE_HEADERS32 peHeader32);
	WORD getSectionOfRVA(QWORD RVA, WORD numberOfSections, PIMAGE_SECTION_HEADER sectionHeaders);
};
#include "PE Dissector.h"


class MainWindow : public QMainWindow
{
	Q_OBJECT

public:
	MainWindow(QWidget *parent = Q_NULLPTR);

public slots:
	void headerTree_selectionChanged();
	void actionOpen_File_triggered();

private:
	Ui::MainWindowClass ui;
	QLabel* statusBarLabel;
	bool addFile(QString filename);
};
