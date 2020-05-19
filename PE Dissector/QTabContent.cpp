#include "QTabContent.h"

QTabContent::QTabContent(QString fileName, PPE_HEADERS32 peHeaders, bool displayListView, bool displayHexView)
{
	this->fileName = fileName;
	this->peHeaders = peHeaders;

	listView = new QTableWidget(0, 0, this);
	listView->verticalHeader()->hide(); // Hide first Column which is not used

	hexView = new QHexView(this);
	hexView->setReadOnly(true);
	hexView->setDocument(QHexDocument::fromFile<QMemoryBuffer>(this->fileName, hexView));
	hexView->document()->metadata()->clear();

	hBoxLayout = new QHBoxLayout();
	hBoxLayout->addWidget(listView);
	hBoxLayout->addWidget(hexView);
	hBoxLayout->setContentsMargins(0, 0, 0, 0);
	hBoxLayout->setSpacing(1);
	this->setLayout(hBoxLayout);

	listView->setHidden(!displayListView);
	hexView->setHidden(!displayHexView);

	constructTreeRootItem();
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
		QTreeWidgetItem* treeExportDirectoryItem = new QTreeWidgetItem(TREE_ITEM_TYPE_EXPORT_DIRECTORY);// treeRootItem);
		treeExportDirectoryItem->setText(0, "Export Directory");
		treeExportDirectoryItem->setIcon(0, folderIcon);
		treeRootItem->addChild(treeExportDirectoryItem);

		QTreeWidgetItem* treeExportedFunctionsItem = new QTreeWidgetItem(TREE_ITEM_TYPE_EXPORTED_FUNCTIONS);
		treeExportedFunctionsItem->setText(0, "Exported Functions");
		treeExportedFunctionsItem->setIcon(0, headerIcon);
		treeExportDirectoryItem->addChild(treeExportedFunctionsItem);
	}

	// Import Directory
	if (peHeaders->ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress > 0)
	{
		QTreeWidgetItem* treeImportDirecotryItem = new QTreeWidgetItem(TREE_ITEM_TYPE_IMPORT_DIRECTORY);// treeRootItem);
		treeImportDirecotryItem->setText(0, "Import Directory");
		treeImportDirecotryItem->setIcon(0, folderIcon);
		treeRootItem->addChild(treeImportDirecotryItem);
		
		// Import Descriptors (DLLs)
		if (peHeaders->ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size % 0x14 == 0)
		{
			QTreeWidgetItem* treeImportedDLLItem;
			for (int i = 0; i < ((peHeaders->ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size / 0x14) - 1); i++)
			{
				QWORD fileOffsetOfName = getFileOffsetFromRVA(peHeaders->importDescriptors[i].Name, peHeaders);
				if (fileOffsetOfName != (QWORD)-1)
				{
					treeImportedDLLItem = new QTreeWidgetItem(TREE_ITEM_TYPE_IMPORTED_DLL + i);
					// This is a temporary solution to get the name of the DLL.
					treeImportedDLLItem->setText(0, QString(hexView->document()->read(fileOffsetOfName, MAX_PATH)));
					treeImportedDLLItem->setIcon(0, dllFileIcon);
					treeImportDirecotryItem->addChild(treeImportedDLLItem);
				}
			}
		}
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
		constructListViewExportDirectory();
		break;

	case TREE_ITEM_TYPE_EXPORTED_FUNCTIONS:
		constructListViewExportedFunctions();
		break;

	case TREE_ITEM_TYPE_IMPORT_DIRECTORY:
		constructListViewImportDirectory();
		break;

	case TREE_ITEM_TYPE_RESOURCE_DIRECTORY:
		constructListViewResourceDirectory();
		break;

	case TREE_ITEM_TYPE_DEBUG_DIRECTORY:
		constructListViewDebugDirectory();
		break;

	case TREE_ITEM_TYPE_TLS_DIRECTORY:
		constructListViewTLSDirectory();
		break;

	default:
		break;
	}
	listView->verticalHeader()->resizeSections(QHeaderView::ResizeToContents);
}

void QTabContent::constructListViewFileInfos()
{
	listView->setColumnCount(2);
	listView->setHorizontalHeaderLabels(QStringList() << "" << "Value");
	listView->setRowCount(5);
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
	int memberOffset = 0;
	int fileOffset = 0;

	// SHOULD CHECKS IF WE HAVE A 64 BITS PE.
	for (int i = 0; dosHeaderMembers[i].size; i++)
	{
		listView->insertRow(i);
		listView->setItem(i, 0, new QTableWidgetItem(QString(dosHeaderMembers[i].name)));						// Member
		listView->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(fileOffset + memberOffset, 8, 16, QChar('0')).toUpper()));	// Offset
		listView->setItem(i, 2, new QTableWidgetItem(QString(dosHeaderMembers[i].sizeTitle)));					// Size
		// This mess allows me to access the header struct as an array or a memory buffer.
		switch (dosHeaderMembers[i].size)																		// Value
		{
		case 1: listView->setItem(i, 3, new QTableWidgetItem(QString("%1").arg(*(BYTE*)((BYTE*)&(peHeaders->dosHeader) + memberOffset), 2 * sizeof(BYTE), 16, QChar('0')).toUpper())); break;
		case 2: listView->setItem(i, 3, new QTableWidgetItem(QString("%1").arg(*(WORD*)((BYTE*)&(peHeaders->dosHeader) + memberOffset), 2 * sizeof(WORD), 16, QChar('0')).toUpper())); break;
		case 4: listView->setItem(i, 3, new QTableWidgetItem(QString("%1").arg(*(DWORD*)((BYTE*)&(peHeaders->dosHeader) + memberOffset), 2 * sizeof(DWORD), 16, QChar('0')).toUpper())); break;
		case 8: listView->setItem(i, 3, new QTableWidgetItem(QString("%1").arg(*(QWORD*)((BYTE*)&(peHeaders->dosHeader) + memberOffset), 2 * sizeof(QWORD), 16, QChar('0')).toUpper())); break;
		}

		// WILL ADD MEANING COLUNM CONTENT BELOW
		//if (QString::compare(dosHeaderMembers[i].name, "", Qt::CaseInsensitive))
		//	listView->setItem(i, 4, new QTableWidgetItem(QString("")));
		//else if (QString::compare(dosHeaderMembers[i].name, "", Qt::CaseInsensitive))
		//	listView->setItem(i, 4, new QTableWidgetItem(QString("")));

		memberOffset += dosHeaderMembers[i].size;
	}
}


void QTabContent::constructListViewNTHeaders()
{
	listView->setColumnCount(5);
	listView->setHorizontalHeaderLabels(QStringList() << "Member" << "Offset" << "Size" << "Value" << "Meaning");

	listView->setRowCount(0);
	int memberOffset = 0;
	int fileOffset = peHeaders->dosHeader.e_lfanew;

	// SHOULD CHECKS IF WE HAVE A 64 BITS PE.
	for (int i = 0; ntHeadersMembers[i].size; i++)
	{
		listView->insertRow(i);
		listView->setItem(i, 0, new QTableWidgetItem(QString(ntHeadersMembers[i].name)));						// Member
		listView->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(fileOffset + memberOffset, 8, 16, QChar('0')).toUpper()));	// Offset
		listView->setItem(i, 2, new QTableWidgetItem(QString(ntHeadersMembers[i].sizeTitle)));					// Size
		// This mess allows me to access the header struct as an array or a memory buffer.
		switch (ntHeadersMembers[i].size)																		// Value
		{
		case 1: listView->setItem(i, 3, new QTableWidgetItem(QString("%1").arg(*(BYTE*)((BYTE*)&(peHeaders->ntHeaders) + memberOffset), 2 * sizeof(BYTE), 16, QChar('0')).toUpper())); break;
		case 2: listView->setItem(i, 3, new QTableWidgetItem(QString("%1").arg(*(WORD*)((BYTE*)&(peHeaders->ntHeaders) + memberOffset), 2 * sizeof(WORD), 16, QChar('0')).toUpper())); break;
		case 4: listView->setItem(i, 3, new QTableWidgetItem(QString("%1").arg(*(DWORD*)((BYTE*)&(peHeaders->ntHeaders) + memberOffset), 2 * sizeof(DWORD), 16, QChar('0')).toUpper())); break;
		case 8: listView->setItem(i, 3, new QTableWidgetItem(QString("%1").arg(*(QWORD*)((BYTE*)&(peHeaders->ntHeaders) + memberOffset), 2 * sizeof(QWORD), 16, QChar('0')).toUpper())); break;
		}

		// WILL ADD MEANING COLUNM CONTENT BELOW
		//if (QString::compare(ntHeadersMembers[i].name, "", Qt::CaseInsensitive))
		//	listView->setItem(i, 4, new QTableWidgetItem(QString("")));
		//else if (QString::compare(ntHeadersMembers[i].name, "", Qt::CaseInsensitive))
		//	listView->setItem(i, 4, new QTableWidgetItem(QString("")));

		memberOffset += ntHeadersMembers[i].size;
	}
}

void QTabContent::constructListViewFileHeader()
{
	listView->setColumnCount(5);
	listView->setHorizontalHeaderLabels(QStringList() << "Member" << "Offset" << "Size" << "Value" << "Meaning");

	listView->setRowCount(0);
	int memberOffset = 0;
	int fileOffset = peHeaders->dosHeader.e_lfanew + sizeof(peHeaders->ntHeaders.Signature);

	// SHOULD CHECKS IF WE HAVE A 64 BITS PE.
	for (int i = 0; fileHeaderMembers[i].size; i++)
	{
		listView->insertRow(i);
		listView->setItem(i, 0, new QTableWidgetItem(QString(fileHeaderMembers[i].name)));						// Member
		listView->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(fileOffset + memberOffset, 8, 16, QChar('0')).toUpper()));	// Offset
		listView->setItem(i, 2, new QTableWidgetItem(QString(fileHeaderMembers[i].sizeTitle)));					// Size
		// This mess allows me to access the header struct as an array or a memory buffer.
		switch (fileHeaderMembers[i].size)																		// Value
		{
		case 1: listView->setItem(i, 3, new QTableWidgetItem(QString("%1").arg(*(BYTE*)((BYTE*)&(peHeaders->ntHeaders.FileHeader) + memberOffset), 2 * sizeof(BYTE), 16, QChar('0')).toUpper())); break;
		case 2: listView->setItem(i, 3, new QTableWidgetItem(QString("%1").arg(*(WORD*)((BYTE*)&(peHeaders->ntHeaders.FileHeader) + memberOffset), 2 * sizeof(WORD), 16, QChar('0')).toUpper())); break;
		case 4: listView->setItem(i, 3, new QTableWidgetItem(QString("%1").arg(*(DWORD*)((BYTE*)&(peHeaders->ntHeaders.FileHeader) + memberOffset), 2 * sizeof(DWORD), 16, QChar('0')).toUpper())); break;
		case 8: listView->setItem(i, 3, new QTableWidgetItem(QString("%1").arg(*(QWORD*)((BYTE*)&(peHeaders->ntHeaders.FileHeader) + memberOffset), 2 * sizeof(QWORD), 16, QChar('0')).toUpper())); break;
		}

		// WILL ADD MEANING COLUNM CONTENT BELOW
		//if (QString::compare(fileHeaderMembers[i].name, "", Qt::CaseInsensitive))
		//	listView->setItem(i, 4, new QTableWidgetItem(QString("")));
		//else if (QString::compare(fileHeaderMembers[i].name, "", Qt::CaseInsensitive))
		//	listView->setItem(i, 4, new QTableWidgetItem(QString("")));

		memberOffset += fileHeaderMembers[i].size;
	}
}

void QTabContent::constructListViewOptionalHeader()
{
	listView->setColumnCount(5);
	listView->setHorizontalHeaderLabels(QStringList() << "Member" << "Offset" << "Size" << "Value" << "Meaning");

	listView->setRowCount(0);
	int memberOffset = 0;
	int fileOffset = peHeaders->dosHeader.e_lfanew + sizeof(peHeaders->ntHeaders.Signature) + sizeof(peHeaders->ntHeaders.FileHeader);

	// SHOULD CHECKS IF WE HAVE A 64 BITS PE.
	for (int i = 0; optionalHeader32Members[i].size; i++)
	{
		listView->insertRow(i);
		listView->setItem(i, 0, new QTableWidgetItem(QString(optionalHeader32Members[i].name)));				// Member
		listView->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(fileOffset + memberOffset, 8, 16, QChar('0')).toUpper()));	// Offset
		listView->setItem(i, 2, new QTableWidgetItem(QString(optionalHeader32Members[i].sizeTitle)));			// Size
		// This mess allows me to access the header struct as an array or a memory buffer.
		switch (optionalHeader32Members[i].size)																// Value
		{
			case 1: listView->setItem(i, 3, new QTableWidgetItem(QString("%1").arg(*(BYTE*)((BYTE*)&(peHeaders->ntHeaders.OptionalHeader) + memberOffset), 2 * sizeof(BYTE), 16, QChar('0')).toUpper())); break;
			case 2: listView->setItem(i, 3, new QTableWidgetItem(QString("%1").arg(*(WORD*)((BYTE*)&(peHeaders->ntHeaders.OptionalHeader) + memberOffset), 2 * sizeof(WORD), 16, QChar('0')).toUpper())); break;
			case 4: listView->setItem(i, 3, new QTableWidgetItem(QString("%1").arg(*(DWORD*)((BYTE*)&(peHeaders->ntHeaders.OptionalHeader) + memberOffset), 2 * sizeof(DWORD), 16, QChar('0')).toUpper())); break;
			case 8: listView->setItem(i, 3, new QTableWidgetItem(QString("%1").arg(*(QWORD*)((BYTE*)&(peHeaders->ntHeaders.OptionalHeader) + memberOffset), 2 * sizeof(QWORD), 16, QChar('0')).toUpper())); break;
		}

		// WILL ADD MEANING COLUNM CONTENT BELOW
		//if (QString::compare(optionalHeader32Members[i].name, "", Qt::CaseInsensitive))
		//	listView->setItem(i, 4, new QTableWidgetItem(QString("")));
		//else if (QString::compare(optionalHeader32Members[i].name, "", Qt::CaseInsensitive))
		//	listView->setItem(i, 4, new QTableWidgetItem(QString("")));

		memberOffset += optionalHeader32Members[i].size;
	}
}

void QTabContent::constructListViewDataDirectories()
{
	listView->setColumnCount(5);
	listView->setHorizontalHeaderLabels(QStringList() << "Member" << "Offset" << "Size" << "Value" << "Section");

	listView->setRowCount(0);
	int memberOffset = 0;
	int fileOffset = peHeaders->dosHeader.e_lfanew + sizeof(peHeaders->ntHeaders.Signature) 
		+ sizeof(peHeaders->ntHeaders.FileHeader) + sizeof(peHeaders->ntHeaders.OptionalHeader) 
		- sizeof(peHeaders->ntHeaders.OptionalHeader.DataDirectory);

	// SHOULD CHECKS IF WE HAVE A 64 BITS PE.
	// We could check i < 32 but we do as for the other sections
	for (int i = 0; dataDirectoriesMembers[i].size; i++)
	{
		listView->insertRow(i);
		listView->setItem(i, 0, new QTableWidgetItem(QString(dataDirectoriesMembers[i].name)));					// Member
		listView->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(fileOffset + memberOffset, 8, 16, QChar('0')).toUpper()));	// Offset
		listView->setItem(i, 2, new QTableWidgetItem(QString(dataDirectoriesMembers[i].sizeTitle)));			// Size
		// This mess allows me to access the header struct as an array or a memory buffer.
		switch (dataDirectoriesMembers[i].size)																	// Value
		{
		case 1: listView->setItem(i, 3, new QTableWidgetItem(QString("%1").arg(*(BYTE*)((BYTE*)(peHeaders->ntHeaders.OptionalHeader.DataDirectory) + memberOffset), 2 * sizeof(BYTE), 16, QChar('0')).toUpper())); break;
		case 2: listView->setItem(i, 3, new QTableWidgetItem(QString("%1").arg(*(WORD*)((BYTE*)(peHeaders->ntHeaders.OptionalHeader.DataDirectory) + memberOffset), 2 * sizeof(WORD), 16, QChar('0')).toUpper())); break;
		case 4: listView->setItem(i, 3, new QTableWidgetItem(QString("%1").arg(*(DWORD*)((BYTE*)(peHeaders->ntHeaders.OptionalHeader.DataDirectory) + memberOffset), 2 * sizeof(DWORD), 16, QChar('0')).toUpper())); break;
		case 8: listView->setItem(i, 3, new QTableWidgetItem(QString("%1").arg(*(QWORD*)((BYTE*)(peHeaders->ntHeaders.OptionalHeader.DataDirectory) + memberOffset), 2 * sizeof(QWORD), 16, QChar('0')).toUpper())); break;
		}

		// if i is even, it means the item is RVA, so we try to display the sections
		if (i % 2 == 0)
		{
			WORD sectionNumber = getSectionFromRVA(peHeaders->ntHeaders.OptionalHeader.DataDirectory[i/2].VirtualAddress,
				peHeaders->ntHeaders.FileHeader.NumberOfSections, peHeaders->sectionHeaders);
			// Checks if the RVA is indeed in a section.
			if (sectionNumber != (WORD)-1)
				listView->setItem(i, 4, new QTableWidgetItem(QString(QByteArray((char*)peHeaders->sectionHeaders[sectionNumber].Name, 8))));
		}

		memberOffset += dataDirectoriesMembers[i].size;
	}
}

void QTabContent::constructListViewSectionHeader()
{
	// This display of the section header is a copy from CCF Explorer but is subject to change to a more detailed view more like the other headers.
	listView->setColumnCount(10);
	listView->setHorizontalHeaderLabels(QStringList() << "Name" << "Virtual Size" << "Virtual Address" << "Raw Size" << "Raw Address"
		<< "Reloc Address" << "Linenumbers" << "Relocations Number" << "Linenumbers Number" << "Characteristics");
	listView->setRowCount(0);
	int memberOffset = 0;
	int fileOffset = peHeaders->dosHeader.e_lfanew + sizeof(peHeaders->ntHeaders);

	for (int i = 0; i < peHeaders->ntHeaders.FileHeader.NumberOfSections; i++)
	{
		listView->insertRow(i);
		listView->setItem(i, 0, new QTableWidgetItem(QString(QByteArray((char*)peHeaders->sectionHeaders[i].Name, 8))));
		listView->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(peHeaders->sectionHeaders[i].Misc.VirtualSize, 2 * sizeof(peHeaders->sectionHeaders[i].Misc.VirtualSize), 16, QChar('0')).toUpper()));
		listView->setItem(i, 2, new QTableWidgetItem(QString("%1").arg(peHeaders->sectionHeaders[i].VirtualAddress, 2 * sizeof(peHeaders->sectionHeaders[i].VirtualAddress), 16, QChar('0')).toUpper()));
		listView->setItem(i, 3, new QTableWidgetItem(QString("%1").arg(peHeaders->sectionHeaders[i].SizeOfRawData, 2 * sizeof(peHeaders->sectionHeaders[i].SizeOfRawData), 16, QChar('0')).toUpper()));
		listView->setItem(i, 4, new QTableWidgetItem(QString("%1").arg(peHeaders->sectionHeaders[i].PointerToRawData, 2 * sizeof(peHeaders->sectionHeaders[i].PointerToRawData), 16, QChar('0')).toUpper()));
		listView->setItem(i, 5, new QTableWidgetItem(QString("%1").arg(peHeaders->sectionHeaders[i].PointerToRelocations, 2 * sizeof(peHeaders->sectionHeaders[i].PointerToRelocations), 16, QChar('0')).toUpper()));
		listView->setItem(i, 6, new QTableWidgetItem(QString("%1").arg(peHeaders->sectionHeaders[i].PointerToLinenumbers, 2 * sizeof(peHeaders->sectionHeaders[i].PointerToLinenumbers), 16, QChar('0')).toUpper()));
		listView->setItem(i, 7, new QTableWidgetItem(QString("%1").arg(peHeaders->sectionHeaders[i].NumberOfRelocations, 2 * sizeof(peHeaders->sectionHeaders[i].NumberOfRelocations), 16, QChar('0')).toUpper()));
		listView->setItem(i, 8, new QTableWidgetItem(QString("%1").arg(peHeaders->sectionHeaders[i].NumberOfLinenumbers, 2 * sizeof(peHeaders->sectionHeaders[i].NumberOfLinenumbers), 16, QChar('0')).toUpper()));
		listView->setItem(i, 9, new QTableWidgetItem(QString("%1").arg(peHeaders->sectionHeaders[i].Characteristics, 2 * sizeof(peHeaders->sectionHeaders[i].Characteristics), 16, QChar('0')).toUpper()));
	}
}

void QTabContent::constructListViewExportDirectory()
{
	listView->setColumnCount(5);
	listView->setHorizontalHeaderLabels(QStringList() << "Member" << "Offset" << "Size" << "Value" << "Meaning");

	listView->setRowCount(0);
	int memberOffset = 0;
	int fileOffset = getFileOffsetFromRVA(peHeaders->ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, peHeaders);

	// SHOULD CHECKS IF WE HAVE A 64 BITS PE.
	for (int i = 0; exportDirectoryMembers[i].size; i++)
	{
		listView->insertRow(i);
		listView->setItem(i, 0, new QTableWidgetItem(QString(exportDirectoryMembers[i].name)));						// Member
		listView->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(fileOffset + memberOffset, 8, 16, QChar('0')).toUpper()));	// Offset
		listView->setItem(i, 2, new QTableWidgetItem(QString(exportDirectoryMembers[i].sizeTitle)));					// Size
		// This mess allows me to access the header struct as an array or a memory buffer.
		switch (exportDirectoryMembers[i].size)																		// Value
		{
		case 1: listView->setItem(i, 3, new QTableWidgetItem(QString("%1").arg(*(BYTE*)((BYTE*)&(peHeaders->exportDirectory) + memberOffset), 2 * sizeof(BYTE), 16, QChar('0')).toUpper())); break;
		case 2: listView->setItem(i, 3, new QTableWidgetItem(QString("%1").arg(*(WORD*)((BYTE*)&(peHeaders->exportDirectory) + memberOffset), 2 * sizeof(WORD), 16, QChar('0')).toUpper())); break;
		case 4: listView->setItem(i, 3, new QTableWidgetItem(QString("%1").arg(*(DWORD*)((BYTE*)&(peHeaders->exportDirectory) + memberOffset), 2 * sizeof(DWORD), 16, QChar('0')).toUpper())); break;
		case 8: listView->setItem(i, 3, new QTableWidgetItem(QString("%1").arg(*(QWORD*)((BYTE*)&(peHeaders->exportDirectory) + memberOffset), 2 * sizeof(QWORD), 16, QChar('0')).toUpper())); break;
		}

		// WILL ADD MEANING COLUNM CONTENT BELOW
		//if (QString::compare(dosHeaderMembers[i].name, "", Qt::CaseInsensitive))
		//	listView->setItem(i, 4, new QTableWidgetItem(QString("")));
		//else if (QString::compare(dosHeaderMembers[i].name, "", Qt::CaseInsensitive))
		//	listView->setItem(i, 4, new QTableWidgetItem(QString("")));

		memberOffset += exportDirectoryMembers[i].size;
	}
}

void QTabContent::constructListViewExportedFunctions()
{
	listView->setColumnCount(5);
	listView->setHorizontalHeaderLabels(QStringList() << "Name" << "Ordinal" << "Function RVA" << "Name RVA" << "Name Ordinal");

	listView->setRowCount(0);
	// Offsets (to be implemented)
	listView->insertRow(0);
	listView->setItem(0, 0, new QTableWidgetItem(QString("")));
	listView->setItem(0, 1, new QTableWidgetItem(QString("")));
	listView->setItem(0, 2, new QTableWidgetItem(QString("")));
	listView->setItem(0, 3, new QTableWidgetItem(QString("")));
	listView->setItem(0, 4, new QTableWidgetItem(QString("")));
	// Types
	listView->insertRow(1);
	listView->setItem(1, 0, new QTableWidgetItem(QString("STRING")));
	listView->setItem(1, 1, new QTableWidgetItem(QString("(index)")));
	listView->setItem(1, 2, new QTableWidgetItem(QString("DWORD")));
	listView->setItem(1, 3, new QTableWidgetItem(QString("DWORD")));
	listView->setItem(1, 4, new QTableWidgetItem(QString("WORD")));

	for (int i = 0; i < peHeaders->exportDirectory.NumberOfFunctions; i++)
	{
		listView->insertRow(i + 2); // +2 Because we have offsets and types above.
		listView->setItem(i + 2, 0, new QTableWidgetItem(QString(hexView->document()->read(getFileOffsetFromRVA(peHeaders->addressOfExportedNames[i], peHeaders), MAX_PATH))));
		listView->setItem(i + 2, 1, new QTableWidgetItem(QString("%1").arg(i, 8, 10, QChar('0'))));
		listView->setItem(i + 2, 2, new QTableWidgetItem(QString("%1").arg(peHeaders->addressOfExportedFunctions[i], 2 * sizeof(DWORD), 16, QChar('0')).toUpper()));
		listView->setItem(i + 2, 3, new QTableWidgetItem(QString("%1").arg(peHeaders->addressOfExportedNames[i], 2 * sizeof(DWORD), 16, QChar('0')).toUpper()));
		listView->setItem(i + 2, 4, new QTableWidgetItem(QString("%1").arg(peHeaders->addressOfExportedNameOrdinals[i], 2 * sizeof(WORD), 16, QChar('0')).toUpper()));
	}
}

void QTabContent::constructListViewImportDirectory()
{
	listView->setColumnCount(7);
	listView->setHorizontalHeaderLabels(QStringList() << "Module Name" << "Imports" << "INT (OFT)" << "TimeDateStamp" << "ForwarderChain" << "Name RVA" << "IAT (FT)");

	listView->setRowCount(0);
	// Offsets (to be implemented)
	listView->insertRow(0);
	listView->setItem(0, 0, new QTableWidgetItem(QString("")));
	listView->setItem(0, 1, new QTableWidgetItem(QString("")));
	listView->setItem(0, 2, new QTableWidgetItem(QString("")));
	listView->setItem(0, 3, new QTableWidgetItem(QString("")));
	listView->setItem(0, 4, new QTableWidgetItem(QString("")));
	listView->setItem(0, 5, new QTableWidgetItem(QString("")));
	listView->setItem(0, 6, new QTableWidgetItem(QString("")));
	// Types
	listView->insertRow(1);
	listView->setItem(1, 0, new QTableWidgetItem(QString("STRING")));
	listView->setItem(1, 1, new QTableWidgetItem(QString("(nFunctions)")));
	listView->setItem(1, 2, new QTableWidgetItem(QString("DWORD")));
	listView->setItem(1, 3, new QTableWidgetItem(QString("DWORD")));
	listView->setItem(1, 4, new QTableWidgetItem(QString("DWORD")));
	listView->setItem(1, 5, new QTableWidgetItem(QString("DWORD")));
	listView->setItem(1, 6, new QTableWidgetItem(QString("DWORD")));

	for (int i = 0; i < ((peHeaders->ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size / 0x14) - 1); i++)
	{
		QWORD fileOffsetOfName = getFileOffsetFromRVA(peHeaders->importDescriptors[i].Name, peHeaders);
		if (fileOffsetOfName != (QWORD)-1)
		{
			listView->insertRow(i + 2); // +2 Because we have offsets and types above.
			// This is a temporary solution to get the name of the DLL.
			listView->setItem(i + 2, 0, new QTableWidgetItem(QString(hexView->document()->read(fileOffsetOfName, MAX_PATH))));
			listView->setItem(i + 2, 1, new QTableWidgetItem(QString("%1").arg(142, 3, 10, QChar('0'))));
			listView->setItem(i + 2, 2, new QTableWidgetItem(QString("%1").arg(peHeaders->importDescriptors[i].OriginalFirstThunk, 2 * sizeof(DWORD), 16, QChar('0')).toUpper()));
			listView->setItem(i + 2, 3, new QTableWidgetItem(QString("%1").arg(peHeaders->importDescriptors[i].TimeDateStamp, 2 * sizeof(DWORD), 16, QChar('0')).toUpper()));
			listView->setItem(i + 2, 4, new QTableWidgetItem(QString("%1").arg(peHeaders->importDescriptors[i].ForwarderChain, 2 * sizeof(DWORD), 16, QChar('0')).toUpper()));
			listView->setItem(i + 2, 5, new QTableWidgetItem(QString("%1").arg(peHeaders->importDescriptors[i].Name, 2 * sizeof(DWORD), 16, QChar('0')).toUpper()));
			listView->setItem(i + 2, 6, new QTableWidgetItem(QString("%1").arg(peHeaders->importDescriptors[i].FirstThunk, 2 * sizeof(DWORD), 16, QChar('0')).toUpper()));
		}
	}
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

