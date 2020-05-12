#include "QTabContent.h"

QTabContent::QTabContent(QString filename, PPE_HEADERS32 peHeaders, bool displayListView, bool displayHexView)
{
	this->filename = filename;
	this->peHeaders = peHeaders;
	constructTreeRootItem();

	listView = new QTableWidget(0, 0, this);

	hexView = new QHexView(this);
	hexView->setReadOnly(true);
	hexDocument = QHexDocument::fromFile<QMemoryBuffer>(this->filename, hexView);
	hexView->setDocument(hexDocument);
	hexMetadata = hexDocument->metadata();
	hexMetadata->clear();

	hBoxLayout = new QHBoxLayout();
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
	qDebug() << "Contructing tree root item";
	QIcon exeFileIcon = QIcon(":/MainWindow/Resources/FileEXE_16x.png");
	QIcon dllFileIcon = QIcon(":/MainWindow/Resources/FileDLL_16x.png");
	QIcon scrFileIcon = QIcon(":/MainWindow/Resources/FileSCR_16x.png");
	QIcon headerIcon = QIcon(":/MainWindow/Resources/PageHeader_blue_16x.png");
	QIcon folderIcon = QIcon(":/MainWindow/Resources/FolderClosed_16x.png");


	treeRootItem = new QTreeWidgetItem(TREE_ITEM_TYPE_BASE_IMAGE);
	treeRootItem->setText(0, QFileInfo(filename).fileName());
	if (!QString::compare(QFileInfo(filename).completeSuffix(), QString("exe"), Qt::CaseInsensitive))
		treeRootItem->setIcon(0, exeFileIcon);
	else if (!QString::compare(QFileInfo(filename).completeSuffix(), QString("scr"), Qt::CaseInsensitive))
		treeRootItem->setIcon(0, scrFileIcon);
	else
		treeRootItem->setIcon(0, dllFileIcon);

	// DOS Header
	QTreeWidgetItem* treeDOSHeaderItem = new QTreeWidgetItem(TREE_ITEM_TYPE_DOS_HEADER);// treeRootItem);
	treeDOSHeaderItem->setText(0, "DOS Header");
	treeDOSHeaderItem->setIcon(0, headerIcon);
	treeRootItem->addChild(treeDOSHeaderItem);

	// NT Headers
	QTreeWidgetItem* treeNTHeadersItem = new QTreeWidgetItem(TREE_ITEM_TYPE_NTS_HEADERS);// treeRootItem);
	treeNTHeadersItem->setText(0, "NT Headers");
	treeNTHeadersItem->setIcon(0, headerIcon);
	treeRootItem->addChild(treeNTHeadersItem);

	// File Header
	QTreeWidgetItem* treeFileHeaderItem = new QTreeWidgetItem(TREE_ITEM_TYPE_FILE_HEADER);// treeNTHeadersItem);
	treeFileHeaderItem->setText(0, "File Header");
	treeFileHeaderItem->setIcon(0, headerIcon);
	treeNTHeadersItem->addChild(treeFileHeaderItem);

	// Optional Header
	QTreeWidgetItem* treeOptionalHeaderItem = new QTreeWidgetItem(TREE_ITEM_TYPE_OPTIONAL_HEADER);// treeNTHeadersItem);
	treeOptionalHeaderItem->setText(0, "Optional Header");
	treeOptionalHeaderItem->setIcon(0, headerIcon);
	treeNTHeadersItem->addChild(treeOptionalHeaderItem);

	// Data Directories
	QTreeWidgetItem* treeDataDirectoriesItem = new QTreeWidgetItem(TREE_ITEM_TYPE_DATA_DIRECTORIES);// treeOptionalHeaderItem);
	treeDataDirectoriesItem->setText(0, "Data Directories");
	treeDataDirectoriesItem->setIcon(0, headerIcon);
	treeOptionalHeaderItem->addChild(treeDataDirectoriesItem);

	// Section Headers
	QTreeWidgetItem* treeSectionHeadersItem = new QTreeWidgetItem(TREE_ITEM_TYPE_SECTION_HEADERS);// treeRootItem);
	treeSectionHeadersItem->setText(0, "Section Headers");
	treeSectionHeadersItem->setIcon(0, headerIcon);
	treeRootItem->addChild(treeSectionHeadersItem);

	// Export Directory
	if (peHeaders->ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress > 0)
	{
		QTreeWidgetItem* treeExportDirecotryItem = new QTreeWidgetItem(TREE_ITEM_TYPE_EXPORT_DIRECTORY);// treeRootItem);
		treeExportDirecotryItem->setText(0, "Export Directory");
		treeExportDirecotryItem->setIcon(0, folderIcon);
		treeRootItem->addChild(treeExportDirecotryItem);
	}

	// Import Directory
	if (peHeaders->ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress > 0)
	{
		QTreeWidgetItem* treeImportDirecotryItem = new QTreeWidgetItem(TREE_ITEM_TYPE_IMPORT_DIRECTORY);// treeRootItem);
		treeImportDirecotryItem->setText(0, "Import Directory");
		treeImportDirecotryItem->setIcon(0, folderIcon);
		treeRootItem->addChild(treeImportDirecotryItem);
		// Import Descriptors
		// if ()
	}

	// Resource Directory
	if (peHeaders->ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress > 0)
	{
		QTreeWidgetItem* treeResourceDirecotryItem = new QTreeWidgetItem(TREE_ITEM_TYPE_RESOURCE_DIRECTORY);// treeRootItem);
		treeResourceDirecotryItem->setText(0, "Resource Directory");
		treeResourceDirecotryItem->setIcon(0, folderIcon);
		treeRootItem->addChild(treeResourceDirecotryItem);
	}

	// Debug Directory
	if (peHeaders->ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress > 0)
	{
		QTreeWidgetItem* treeDebugDirecotryItem = new QTreeWidgetItem(TREE_ITEM_TYPE_DEBUG_DIRECTORY);// treeRootItem);
		treeDebugDirecotryItem->setText(0, "Debug Directory");
		treeDebugDirecotryItem->setIcon(0, folderIcon);
		treeRootItem->addChild(treeDebugDirecotryItem);
	}

	// TLS Directory
	if (peHeaders->ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress > 0)
	{
		QTreeWidgetItem* treeTLSDirecotryItem = new QTreeWidgetItem(TREE_ITEM_TYPE_TLS_DIRECTORY);// treeRootItem);
		treeTLSDirecotryItem->setText(0, "TLS Directory");
		treeTLSDirecotryItem->setIcon(0, folderIcon);
		treeRootItem->addChild(treeTLSDirecotryItem);
	}

	// More to come
}

void QTabContent::constructListView(int treeItemType)
{
	qDebug() << "construct List View, type : " << treeItemType;

	listView->clear();
	switch (treeItemType)
	{
	case TREE_ITEM_TYPE_BASE_IMAGE:
		break;

	case TREE_ITEM_TYPE_DOS_HEADER:
		constructListViewDOSHeader();
		break;

	case TREE_ITEM_TYPE_NTS_HEADERS:
		break;

	case TREE_ITEM_TYPE_FILE_HEADER:
		break;

	case TREE_ITEM_TYPE_OPTIONAL_HEADER:
		break;

	case TREE_ITEM_TYPE_DATA_DIRECTORIES:
		break;

	case TREE_ITEM_TYPE_SECTION_HEADERS:
		break;

	case TREE_ITEM_TYPE_EXPORT_DIRECTORY:
		break;

	case TREE_ITEM_TYPE_IMPORT_DIRECTORY:
		break;

	case TREE_ITEM_TYPE_RESOURCE_DIRECTORY:
		break;

	case TREE_ITEM_TYPE_DEBUG_DIRECTORY:
		break;

	case TREE_ITEM_TYPE_TLS_DIRECTORY:
		break;

	default:
		break;
	}
}

void QTabContent::constructListViewFileInfos()
{
}

void QTabContent::constructListViewDOSHeader()
{


	listView->setColumnCount(4);
	listView->setHorizontalHeaderLabels(QStringList() << "Member" << "Offset" << "Size" << "Value" << "Meaning");

	int offset = 0;
	for (int i = 0; dosHeaderMembers[i].size; i++)
	{
		listView->insertRow(i);
		listView->setItem(i, 0, new QTableWidgetItem(QString(dosHeaderMembers[i].name)));			// Member
		listView->setItem(i, 1, new QTableWidgetItem(QString::number(offset)));						// Offset
		listView->setItem(i, 2, new QTableWidgetItem(QString(dosHeaderMembers[i].sizeTitle)));		// Size
		listView->setItem(i, 3, new QTableWidgetItem(QString(dosHeaderMembers[i].sizeTitle)));		// Value

		offset += dosHeaderMembers[i].size;
	}
	listView->verticalHeader()->hide(); // Hide first Column which is not used
}

void QTabContent::constructListViewNTHeaders()
{
}

void QTabContent::constructListViewFileHeader()
{
}

void QTabContent::constructListViewOptionalHeader()
{
}

void QTabContent::constructListViewDataDirectories()
{
}

void QTabContent::constructListViewSectionHeader()
{
}

void QTabContent::constructListViewExportDirectory()
{
}

void QTabContent::constructListViewImportDirectory()
{
}

void QTabContent::constructListViewResourceDirectory()
{
}

void QTabContent::constructListViewDebugDirectory()
{
}

void QTabContent::constructListViewTLSDirectory()
{
}

