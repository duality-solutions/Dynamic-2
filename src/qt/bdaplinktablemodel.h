// Copyright (c) 2016-2021 Duality Blockchain Solutions Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DYNAMIC_QT_BDAPLINKTABLEMODEL_H
#define DYNAMIC_QT_BDAPLINKTABLEMODEL_H

#include <QAbstractTableModel>
#include <QStringList>
#include <QTableWidget>
#include <QLabel>

#include <memory>

class BdapPage;
class BdapLinkTablePriv;

QT_BEGIN_NAMESPACE
class QTimer;
QT_END_NAMESPACE

struct CAccountStats2 {
    unsigned int count;
};

/**
   Qt model providing information about BDAP users and groups.
 */
class BdapLinkTableModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    explicit BdapLinkTableModel(BdapPage* parent = 0);
    ~BdapLinkTableModel();

    void refreshComplete();
    void refreshPendingAccept();
    void refreshPendingRequest();
    void refreshAll();
    void startAutoRefresh();
    void stopAutoRefresh();    

    enum ColumnIndex {
        Requestor = 0,
        Recipient = 1,
        Date = 2
    };

    /** @name Methods overridden from QAbstractTableModel
        @{*/
    int rowCount(const QModelIndex& parent) const;
    int columnCount(const QModelIndex& parent) const;
    QVariant data(const QModelIndex& index, int role) const;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const;
    QModelIndex index(int row, int column, const QModelIndex& parent) const;
    Qt::ItemFlags flags(const QModelIndex& index) const;
    void sort(int column, Qt::SortOrder order);
   /*@}*/

public Q_SLOTS:
    void refresh();

private:
    BdapPage* bdapPage;
    QStringList columns;
    QTimer* timer;
    std::unique_ptr<BdapLinkTablePriv> priv;

    QTableWidget* completeTable;
    QLabel* completeStatus;

    QTableWidget* pendingAcceptTable;
    QLabel* pendingAcceptStatus;

    QTableWidget* pendingRequestTable;
    QLabel* pendingRequestStatus;

    std::string searchCompleteRequestor;
    std::string searchCompleteRecipient;  
    std::string searchPARequestor;
    std::string searchPARecipient;          
    std::string searchPRRequestor;
    std::string searchPRRecipient;          
    
};

#endif // DYNAMIC_QT_BDAPLINKTABLEMODEL_H