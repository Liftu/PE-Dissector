#pragma once

#include <QtWidgets/qwidget.h>
#include <QtWidgets/qfiledialog.h>
#include <QtWidgets/qtreewidget.h>
#include <QtWidgets/qlayout.h>
#include <QtWidgets/qtablewidget.h>
#include <QtWidgets/qlabel.h>
#include <QtCore/qdebug.h>

extern "C" typedef struct _PE_HEADERS32 PE_HEADERS32, *PPE_HEADERS32;
#include "PE Dissector.h"
#include "QHexView.h"

class QTabContent : public QWidget
{
	Q_OBJECT

public:
	QTabContent(QString filename, PPE_HEADERS32 peHeaders, bool displayListView, bool displayHexView);
	~QTabContent();
	PPE_HEADERS32 getPEHeaders();
	QTreeWidgetItem* getTreeRootItem();

public slots:
	void actionToggle_List_View_triggered(bool triggered);
	void actionToggle_Hex_View_triggered(bool triggered);

private:
	void constructTreeRootItem();

	QString filename;
	PPE_HEADERS32 peHeaders;
	QTreeWidgetItem* treeRootItem;
	QHBoxLayout* hBoxLayout;
	QTableWidget* listView;
	QHexView* hexView;
};

