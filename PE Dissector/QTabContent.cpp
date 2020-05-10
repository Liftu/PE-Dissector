#include "QTabContent.h"

QTabContent::QTabContent(PE_HEADERS32 peHeaders, bool displayListView, bool displayHexView)
{
	hBoxLayout = new QHBoxLayout();
	listView = new QTableWidget(3,3);
	hexView = new QLabel("There should be a hex view here");
	hBoxLayout->addWidget(listView);
	hBoxLayout->addWidget(hexView);
	hBoxLayout->setContentsMargins(0, 0, 0, 0);
	hBoxLayout->setSpacing(1);
	this->setLayout(hBoxLayout);

	listView->setHidden(!displayListView);
	hexView->setHidden(!displayHexView);
}

void QTabContent::actionToggle_List_View_triggered(bool triggered)
{
	listView->setHidden(!triggered);
}

void QTabContent::actionToggle_Hex_View_triggered(bool triggered)
{
	hexView->setHidden(!triggered);
}
