#include "QTabContent.h"

QTabContent::QTabContent(QString filename, PPE_HEADERS32 peHeaders, bool displayListView, bool displayHexView)
{
	this->fileName = filename;
	this->peHeaders = peHeaders;
	constructTreeRootItem();

	listView = new QTableWidget(0, 0, this);

	hexView = new QHexView(this);
	hexView->setReadOnly(true);
	hexDocument = QHexDocument::fromFile<QMemoryBuffer>(this->fileName, hexView);
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

QString QTabContent::getFileName()
{
	return this->fileName;
}

QString QTabContent::getFileTitle()
{
	return QFileInfo(this->fileName).fileName();
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
	treeRootItem->setText(0, QFileInfo(fileName).fileName());
	if (!QString::compare(QFileInfo(fileName).completeSuffix(), QString("exe"), Qt::CaseInsensitive))
		treeRootItem->setIcon(0, exeFileIcon);
	else if (!QString::compare(QFileInfo(fileName).completeSuffix(), QString("scr"), Qt::CaseInsensitive))
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
	QTreeWidgetItem* treeSectionHeadersItem = new QTreeWidgetItem(TREE_ITEM_TYPE_SECTION_HEADER);// treeRootItem);
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
		constructListViewFileInfos();
		break;

	case TREE_ITEM_TYPE_DOS_HEADER:
		constructListViewDOSHeader();
		break;

	case TREE_ITEM_TYPE_NTS_HEADERS:
		constructListViewNTHeaders();
		break;

	case TREE_ITEM_TYPE_FILE_HEADER:
		constructListViewFileHeader();
		break;

	case TREE_ITEM_TYPE_OPTIONAL_HEADER:
		constructListViewOptionalHeader();
		break;

	case TREE_ITEM_TYPE_DATA_DIRECTORIES:
		constructListViewDataDirectories();
		break;

	case TREE_ITEM_TYPE_SECTION_HEADER:
		constructListViewSectionHeader();
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
	listView->setColumnCount(2);
	listView->setHorizontalHeaderLabels(QStringList() << "" << "Value");
	listView->setRowCount(5);
	listView->verticalHeader()->hide();
	//listView->setVerticalHeaderLabels(QStringList() << "File Path" << "File Type" << "File Size" << "Created" << "MD5");
	listView->setItem(0, 0, new QTableWidgetItem(QString("File Path")));
	listView->setItem(1, 0, new QTableWidgetItem(QString("File Type")));
	listView->setItem(2, 0, new QTableWidgetItem(QString("File Size")));
	listView->setItem(3, 0, new QTableWidgetItem(QString("Created")));
	listView->setItem(4, 0, new QTableWidgetItem(QString("MD5")));
}

void QTabContent::constructListViewDOSHeader()
{
	listView->setColumnCount(5);
	listView->setHorizontalHeaderLabels(QStringList() << "Member" << "Offset" << "Size" << "Value" << "Meaning");

	listView->setRowCount(0);
	int offset = 0;

	// SHOULD CHECKS IF WE HAVE A 64 BITS PE.
	for (int i = 0; dosHeaderMembers[i].size; i++)
	{
		listView->insertRow(i);
		listView->setItem(i, 0, new QTableWidgetItem(QString(dosHeaderMembers[i].name)));								// Member
		listView->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(offset, 8, 16, QChar('0')).toUpper()));	// Offset
		listView->setItem(i, 2, new QTableWidgetItem(QString(dosHeaderMembers[i].sizeTitle)));							// Size
		// This mess allow me to access the header struct as an array or a memory buffer.
		switch (dosHeaderMembers[i].size)																				// Value
		{
		case 1: listView->setItem(i, 3, new QTableWidgetItem(QString("%1").arg(*(BYTE*)((CHAR*)&(peHeaders->dosHeader) + offset), 2 * sizeof(BYTE), 16, QChar('0')).toUpper())); break;
		case 2: listView->setItem(i, 3, new QTableWidgetItem(QString("%1").arg(*(WORD*)((CHAR*)&(peHeaders->dosHeader) + offset), 2 * sizeof(WORD), 16, QChar('0')).toUpper())); break;
		case 4: listView->setItem(i, 3, new QTableWidgetItem(QString("%1").arg(*(DWORD*)((CHAR*)&(peHeaders->dosHeader) + offset), 2 * sizeof(DWORD), 16, QChar('0')).toUpper())); break;
		case 8: listView->setItem(i, 3, new QTableWidgetItem(QString("%1").arg(*(QWORD*)((CHAR*)&(peHeaders->dosHeader) + offset), 2 * sizeof(QWORD), 16, QChar('0')).toUpper())); break;
		}

		// WILL ADD MEANING COLUNM CONTENT BELOW
		//if (QString::compare(dosHeaderMembers[i].name, "", Qt::CaseInsensitive))
		//	listView->setItem(i, 4, new QTableWidgetItem(QString("")));
		//else if (QString::compare(dosHeaderMembers[i].name, "", Qt::CaseInsensitive))
		//	listView->setItem(i, 4, new QTableWidgetItem(QString("")));

		offset += dosHeaderMembers[i].size;
	}
	listView->verticalHeader()->hide(); // Hide first Column which is not used
}


void QTabContent::constructListViewNTHeaders()
{
	listView->setColumnCount(5);
	listView->setHorizontalHeaderLabels(QStringList() << "Member" << "Offset" << "Size" << "Value" << "Meaning");

	listView->setRowCount(0);
	int offset = 0;
	for (int i = 0; ntHeadersMembers[i].size; i++)
	{
		listView->insertRow(i);
		listView->setItem(i, 0, new QTableWidgetItem(QString(ntHeadersMembers[i].name)));			// Member
		listView->setItem(i, 1, new QTableWidgetItem(QString::number(offset)));						// Offset
		listView->setItem(i, 2, new QTableWidgetItem(QString(ntHeadersMembers[i].sizeTitle)));		// Size
		listView->setItem(i, 3, new QTableWidgetItem(QString("")));									// Value

		offset += ntHeadersMembers[i].size;
	}
	listView->verticalHeader()->hide(); // Hide first Column which is not used
}

void QTabContent::constructListViewFileHeader()
{
	listView->setColumnCount(5);
	listView->setHorizontalHeaderLabels(QStringList() << "Member" << "Offset" << "Size" << "Value" << "Meaning");

	listView->setRowCount(0);
	int offset = 0;
	for (int i = 0; fileHeaderMembers[i].size; i++)
	{
		listView->insertRow(i);
		listView->setItem(i, 0, new QTableWidgetItem(QString(fileHeaderMembers[i].name)));			// Member
		listView->setItem(i, 1, new QTableWidgetItem(QString::number(offset)));						// Offset
		listView->setItem(i, 2, new QTableWidgetItem(QString(fileHeaderMembers[i].sizeTitle)));		// Size
		listView->setItem(i, 3, new QTableWidgetItem(QString("")));									// Value

		offset += fileHeaderMembers[i].size;
	}
	listView->verticalHeader()->hide(); // Hide first Column which is not used
}

void QTabContent::constructListViewOptionalHeader()
{
	listView->setColumnCount(5);
	listView->setHorizontalHeaderLabels(QStringList() << "Member" << "Offset" << "Size" << "Value" << "Meaning");

	listView->setRowCount(0);
	int offset = 0;

	// SHOULD CHECKS IF WE HAVE A 64 BITS PE.
	for (int i = 0; optionalHeader32Members[i].size; i++)
	{
		listView->insertRow(i);
		listView->setItem(i, 0, new QTableWidgetItem(QString(optionalHeader32Members[i].name)));								// Member
		listView->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(offset, 8, 16, QChar('0')).toUpper()));	// Offset
		listView->setItem(i, 2, new QTableWidgetItem(QString(optionalHeader32Members[i].sizeTitle)));							// Size
		// This mess allow me to access the header struct as an array or a memory buffer.
		switch (optionalHeader32Members[i].size)																				// Value
		{
			case 1: listView->setItem(i, 3, new QTableWidgetItem(QString("%1").arg(*(BYTE*)((CHAR*)&(peHeaders->ntHeaders.OptionalHeader) + offset), 2 * sizeof(BYTE), 16, QChar('0')).toUpper())); break;
			case 2: listView->setItem(i, 3, new QTableWidgetItem(QString("%1").arg(*(WORD*)((CHAR*)&(peHeaders->ntHeaders.OptionalHeader) + offset), 2 * sizeof(WORD), 16, QChar('0')).toUpper())); break;
			case 4: listView->setItem(i, 3, new QTableWidgetItem(QString("%1").arg(*(DWORD*)((CHAR*)&(peHeaders->ntHeaders.OptionalHeader) + offset), 2 * sizeof(DWORD), 16, QChar('0')).toUpper())); break;
			case 8: listView->setItem(i, 3, new QTableWidgetItem(QString("%1").arg(*(QWORD*)((CHAR*)&(peHeaders->ntHeaders.OptionalHeader) + offset), 2 * sizeof(QWORD), 16, QChar('0')).toUpper())); break;
		}

		// WILL ADD MEANING COLUNM CONTENT BELOW
		//if (QString::compare(optionalHeader32Members[i].name, "", Qt::CaseInsensitive))
		//	listView->setItem(i, 4, new QTableWidgetItem(QString("")));
		//else if (QString::compare(optionalHeader32Members[i].name, "", Qt::CaseInsensitive))
		//	listView->setItem(i, 4, new QTableWidgetItem(QString("")));

		offset += optionalHeader32Members[i].size;
	}
	listView->verticalHeader()->hide(); // Hide first Column which is not used
}

void QTabContent::constructListViewDataDirectories()
{
	listView->setColumnCount(5);
	listView->setHorizontalHeaderLabels(QStringList() << "Member" << "Offset" << "Size" << "Value" << "Meaning");

	listView->setRowCount(0);
	int offset = 0;
	for (int i = 0; dataDirectoriesMembers[i].size; i++)
	{
		listView->insertRow(i);
		listView->setItem(i, 0, new QTableWidgetItem(QString(dataDirectoriesMembers[i].name)));			// Member
		listView->setItem(i, 1, new QTableWidgetItem(QString::number(offset)));							// Offset
		listView->setItem(i, 2, new QTableWidgetItem(QString(dataDirectoriesMembers[i].sizeTitle)));	// Size
		listView->setItem(i, 3, new QTableWidgetItem(QString("")));										// Value

		offset += dataDirectoriesMembers[i].size;
	}
	listView->verticalHeader()->hide(); // Hide first Column which is not used
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

