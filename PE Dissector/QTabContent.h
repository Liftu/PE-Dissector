#pragma once

#include <QtWidgets/qwidget.h>
#include <QtWidgets/qfiledialog.h>
#include <QtWidgets/qtreewidget.h>
#include <QtWidgets/qlayout.h>
#include <QtWidgets/qtablewidget.h>
#include <QtWidgets/qheaderview.h>
#include <QtWidgets/qlabel.h>
#include <QtCore/qdebug.h>

#include <Windows.h>
extern "C" {
	typedef struct _PE_HEADERS32 PE_HEADERS32, *PPE_HEADERS32;
	typedef unsigned __int64 QWORD;
	BOOL isFileExecutable(HANDLE hFile);
	WORD getArchitecture(HANDLE hFile);
	BOOL readPEHeaders32(HANDLE hFile, PPE_HEADERS32 peHeaders32);
	WORD getSectionFromRVA(QWORD RVA, WORD numberOfSections, PIMAGE_SECTION_HEADER sectionHeaders);
	QWORD getFileOffsetFromRVA(QWORD RVA, PPE_HEADERS32 peHearders32);
};
#include "PE Dissector.h"
#include "HeaderMembers.h"
#include "QHexView/qhexview.h"
#include "QHexView/document/buffer/qmemorybuffer.h"

class QTabContent : public QWidget
{
	Q_OBJECT

public:
	QTabContent(QString fileName, PPE_HEADERS32 peHeaders, bool displayListView, bool displayHexView);
	~QTabContent();
	PPE_HEADERS32 getPEHeaders();
	QTreeWidgetItem* getTreeRootItem();
	QString getFileName();
	QString getFileTitle();

	enum
	{
		TREE_ITEM_TYPE_BASE_IMAGE = QTreeWidgetItem::UserType,
		TREE_ITEM_TYPE_DOS_HEADER,
		TREE_ITEM_TYPE_NTS_HEADERS,
		TREE_ITEM_TYPE_FILE_HEADER,
		TREE_ITEM_TYPE_OPTIONAL_HEADER,
		TREE_ITEM_TYPE_DATA_DIRECTORIES,
		TREE_ITEM_TYPE_SECTION_HEADER,
		TREE_ITEM_TYPE_EXPORT_DIRECTORY,
		TREE_ITEM_TYPE_EXPORTED_FUNCTIONS,
		TREE_ITEM_TYPE_IMPORT_DIRECTORY,
		TREE_ITEM_TYPE_RESOURCE_DIRECTORY,
		TREE_ITEM_TYPE_DEBUG_DIRECTORY,
		TREE_ITEM_TYPE_TLS_DIRECTORY,

		// End of the enum because we don't know how many DLLs 
		// are imported and we add 1 for each imported DLL
		TREE_ITEM_TYPE_IMPORTED_DLL = QTreeWidgetItem::UserType + 100,
	};

public slots:
	void actionToggle_List_View_triggered(bool triggered);
	void actionToggle_Hex_View_triggered(bool triggered);
	void constructListView(int treeItemType);

private:
	void constructTreeRootItem();
	void constructListViewFileInfos();
	void constructListViewDOSHeader();
	void constructListViewNTHeaders();
	void constructListViewFileHeader();
	void constructListViewOptionalHeader();
	void constructListViewDataDirectories();
	void constructListViewSectionHeader();
	void constructListViewExportDirectory();
	void constructListViewImportDirectory();
	void constructListViewResourceDirectory();
	void constructListViewDebugDirectory();
	void constructListViewTLSDirectory();

	QString fileName;
	PPE_HEADERS32 peHeaders;
	QTreeWidgetItem* treeRootItem;
	QHBoxLayout* hBoxLayout;
	QTableWidget* listView;
	QHexView* hexView;
};