#pragma once

#include <QtWidgets/qwidget.h>
#include <QtWidgets/qlayout.h>
#include <QtWidgets/qtablewidget.h>
#include <QtWidgets/qlabel.h>
#include <QtCore/qdebug.h>

extern "C" typedef struct _PE_HEADERS32 PE_HEADERS32, *PPE_HEADERS32;
#include "PE Dissector.h"

class QTabContent : public QWidget
{
	Q_OBJECT

public:
	QTabContent(PE_HEADERS32 peHeaders, bool displayListView, bool displayHexView);

public slots:
	void actionToggle_List_View_triggered(bool triggered);
	void actionToggle_Hex_View_triggered(bool triggered);

private:
	QHBoxLayout* hBoxLayout;
	QTableWidget* listView;
	QLabel* hexView;
	// There will be a hex view
	PE_HEADERS32 peHeaders;
};

