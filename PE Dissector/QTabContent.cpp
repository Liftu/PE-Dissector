#include "QTabContent.h"

QTabContent::QTabContent(QString filename, PPE_HEADERS32 peHeaders, bool displayListView, bool displayHexView)
{
	this->filename = filename;
	this->peHeaders = peHeaders;
	constructTreeRootItem();

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

QTabContent::~QTabContent()
{
	qDebug() << "QTabContent destruction.";
	delete hBoxLayout;
	delete listView;
	delete hexView;
}

PPE_HEADERS32 QTabContent::getPEHeaders()
{
	return this->peHeaders;
}

QTreeWidgetItem * QTabContent::getTreeRootItem()
{
	return this->treeRootItem;
}

void QTabContent::actionToggle_List_View_triggered(bool triggered)
{
	listView->setHidden(!triggered);
}

void QTabContent::actionToggle_Hex_View_triggered(bool triggered)
{
	hexView->setHidden(!triggered);
}

void QTabContent::constructTreeRootItem()
{
	treeRootItem = new QTreeWidgetItem();
	treeRootItem->setText(0, QFileInfo(filename).fileName());

	// DOS Header
	QTreeWidgetItem* treeDOSHeaderItem = new QTreeWidgetItem();// treeRootItem);
	treeDOSHeaderItem->setText(0, "DOS Header");
	treeRootItem->addChild(treeDOSHeaderItem);

	// NT Headers
	QTreeWidgetItem* treeNTHeadersItem = new QTreeWidgetItem();// treeRootItem);
	treeNTHeadersItem->setText(0, "NT Headers");
	treeRootItem->addChild(treeNTHeadersItem);

	// File Header
	QTreeWidgetItem* treeFileHeaderItem = new QTreeWidgetItem();// treeNTHeadersItem);
	treeFileHeaderItem->setText(0, "File Header");
	treeNTHeadersItem->addChild(treeFileHeaderItem);

	// Optional Header
	QTreeWidgetItem* treeOptionalHeaderItem = new QTreeWidgetItem();// treeNTHeadersItem);
	treeOptionalHeaderItem->setText(0, "Optional Header");
	treeNTHeadersItem->addChild(treeOptionalHeaderItem);

	// Data Directories
	QTreeWidgetItem* treeDataDirectoriesItem = new QTreeWidgetItem();// treeOptionalHeaderItem);
	treeDataDirectoriesItem->setText(0, "Data Directories");
	treeOptionalHeaderItem->addChild(treeDataDirectoriesItem);

	// Section Headers
	QTreeWidgetItem* treeSectionHeadersItem = new QTreeWidgetItem();// treeRootItem);
	treeSectionHeadersItem->setText(0, "Section Headers");
	treeRootItem->addChild(treeSectionHeadersItem);

	// More to come
}
